//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/gasmod/gas"
	"github.com/gasmod/gas/config"

	"tule.dev/console/internal/app"
	"tule.dev/console/internal/awsclient"
	"tule.dev/console/internal/consoletest"
)

// The console runs in-process against the real services, each built from
// its checkout and run as a process on a free port, all with one root key
// and all pointed at the one identity, so a key identity issues works on
// every service. TestMain starts them once for the whole suite.

// The root key every service is configured with: the AWS documentation's
// example key, since identity holds an access key ID to at least 16
// characters.
const (
	rootKeyID  = "AKIAIOSFODNN7EXAMPLE"
	rootSecret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	region     = "us-east-1"
)

// clientTimeout bounds a test's own SDK calls.
const clientTimeout = 60 * time.Second

// services are the checkouts the suite builds, by the name of the
// TULE_E2E_<NAME>_DIR variable that overrides each one's sibling path.
var services = []string{"identity", "accounts", "object-store", "secret-store", "mailbox", "queues"}

// stack is the running suite: each service's base URL, and the console's.
var stack struct {
	urls    map[string]string
	console string
	logs    string
}

var rootCreds = aws.Credentials{AccessKeyID: rootKeyID, SecretAccessKey: rootSecret}

func TestMain(m *testing.M) {
	os.Exit(run(m))
}

func run(m *testing.M) int {
	work, err := os.MkdirTemp("", "tule-console-e2e-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "e2e:", err)
		return 1
	}
	defer func() { _ = os.RemoveAll(work) }()

	procs, err := startServices(work)
	defer func() {
		for _, p := range procs {
			p.stop()
		}
	}()
	if err != nil {
		fmt.Fprintln(os.Stderr, "e2e:", err)
		return 1
	}

	undoFunctions, err := startFunctions(work)
	defer undoFunctions()
	if err != nil {
		fmt.Fprintln(os.Stderr, "e2e: functions:", err)
		return 1
	}
	if fn.skip != "" {
		fmt.Fprintln(os.Stderr, "e2e: the functions tests are skipped:", fn.skip)
	}

	a, url, err := startConsole(work)
	if err != nil {
		fmt.Fprintln(os.Stderr, "e2e: console:", err)
		return 1
	}
	stack.console = url
	code := m.Run()
	if err = a.Stop(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, "e2e: stop console:", err)
		code = 1
	}
	if leak := secretsInLogs(); leak != "" {
		fmt.Fprintln(os.Stderr, "e2e: the console's log holds a secret:", leak)
		code = 1
	}
	return code
}

// process is a running service.
type process struct {
	cmd    *exec.Cmd
	exited chan error
	out    *output
	name   string
}

// output collects a process's output, safe to write from its copying
// goroutines and read from the test.
type output struct {
	buf bytes.Buffer
	mu  sync.Mutex
}

func (o *output) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.buf.Write(p) //nolint:wrapcheck // bytes.Buffer.Write never fails
}

func (o *output) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.buf.String()
}

// startServices builds every service and runs it on a free port, and
// waits until each is ready.
func startServices(work string) ([]*process, error) {
	ports := map[string]int{}
	stack.urls = map[string]string{}
	for _, s := range services {
		p, err := freePort()
		if err != nil {
			return nil, err
		}
		ports[s] = p
		stack.urls[s] = "http://127.0.0.1:" + strconv.Itoa(p)
	}

	var procs []*process
	for _, s := range services {
		bin, err := build(work, s)
		if err != nil {
			return procs, err
		}
		dir := filepath.Join(work, s+"-data")
		if err = os.MkdirAll(dir, 0o700); err != nil {
			return procs, fmt.Errorf("make the store of %s: %w", s, err)
		}
		p, err := start(s, bin, dir, serviceEnv(s, ports[s], dir))
		if err != nil {
			return procs, err
		}
		procs = append(procs, p)
	}
	for _, p := range procs {
		if err := p.waitReady(stack.urls[p.name]); err != nil {
			return procs, err
		}
	}
	return procs, nil
}

// serviceEnv is the environment of service s: its port and store, the
// root key, and identity's endpoint, or for identity, accounts'.
func serviceEnv(s string, port int, dir string) []string {
	env := []string{
		"TULE_GasEnv=testing",
		"TULE_Server_Port=" + strconv.Itoa(port),
		"TULE_Auth_AccessKeyID=" + rootKeyID,
		"TULE_Auth_SecretAccessKey=" + rootSecret,
	}
	switch s {
	case "identity":
		return append(env, "TULE_Store_Path="+filepath.Join(dir, "identity.db"),
			"TULE_Identity_AccountsEndpoint="+stack.urls["accounts"])
	case "object-store":
		env = append(env, "TULE_Storage_RootDir="+dir)
	case "secret-store":
		env = append(env, "TULE_Store_RootDir="+dir)
	default:
		env = append(env, "TULE_Store_Path="+filepath.Join(dir, s+".db"))
	}
	return append(env, "TULE_Auth_IdentityEndpoint="+stack.urls["identity"])
}

// build builds the service from its checkout: TULE_E2E_<NAME>_DIR, or the
// console's sibling. A missing checkout fails the suite rather than being
// skipped.
func build(work, s string) (string, error) {
	envName := "TULE_E2E_" + strings.ToUpper(strings.ReplaceAll(s, "-", "_")) + "_DIR"
	src := os.Getenv(envName)
	if src == "" {
		src = filepath.Join("..", "..", "..", s)
	}
	src, err := filepath.Abs(src)
	if err != nil {
		return "", fmt.Errorf("%s checkout: %w", s, err)
	}
	//nolint:gosec // G703: the checkout the suite is told to build
	if _, err = os.Stat(filepath.Join(src, "go.mod")); err != nil {
		return "", fmt.Errorf("no %s checkout at %s; set %s: %w", s, src, envName, err)
	}
	bin := filepath.Join(work, "tule-"+s)
	//nolint:gosec // G204: go build of the checkout
	cmd := exec.Command("go", "build", "-o", bin, "./cmd")
	cmd.Dir = src
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("build %s: %w\n%s", s, err, out)
	}
	return bin, nil
}

func start(name, bin, dir string, env []string) (*process, error) {
	cmd := exec.Command(bin) //nolint:gosec // G204: the binary the suite just built
	cmd.Dir = dir
	cmd.Env = append(envWithoutTule(), env...)
	p := &process{cmd: cmd, exited: make(chan error, 1), out: &output{}, name: name}
	cmd.Stdout, cmd.Stderr = p.out, p.out
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %s: %w", name, err)
	}
	go func() { p.exited <- cmd.Wait() }()
	return p, nil
}

func envWithoutTule() []string {
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "TULE_") {
			env = append(env, kv)
		}
	}
	return env
}

func (p *process) waitReady(url string) error {
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(clientTimeout)
	for time.Now().Before(deadline) {
		select {
		case err := <-p.exited:
			return fmt.Errorf("%s exited before it was ready: %w\n%s", p.name, err, p.out.String())
		default:
		}
		req, err := http.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			url+"/_ready",
			http.NoBody,
		)
		if err != nil {
			return fmt.Errorf("readiness request: %w", err)
		}
		if res, err := client.Do(req); err == nil {
			_ = res.Body.Close()
			if res.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("%s was not ready within %v\n%s", p.name, clientTimeout, p.out.String())
}

// stop interrupts the process, as a signal stops the service, and kills it
// if it does not exit in time.
func (p *process) stop() {
	_ = p.cmd.Process.Signal(os.Interrupt)
	var err error
	select {
	case err = <-p.exited:
	case <-time.After(clientTimeout):
		_ = p.cmd.Process.Kill()
		err = <-p.exited
		_, _ = fmt.Fprintf(
			os.Stderr,
			"e2e: %s did not stop on interrupt\n%s",
			p.name,
			p.out.String(),
		)
	}
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "e2e: %s exited: %v\n", p.name, err)
	}
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("find a free port: %w", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	if err = l.Close(); err != nil {
		return 0, fmt.Errorf("release the free port: %w", err)
	}
	return port, nil
}

// startConsole runs the console in-process, pointed at every service, in
// the development environment so it logs at trace level, its log captured
// in a file the suite checks for secrets at the end.
func startConsole(work string) (*gas.App, string, error) {
	env := map[string]string{
		"TULE_GasEnv":                      "development",
		"TULE_Console_IdentityEndpoint":    stack.urls["identity"],
		"TULE_Console_AccountsEndpoint":    stack.urls["accounts"],
		"TULE_Console_ObjectStoreEndpoint": stack.urls["object-store"],
		"TULE_Console_SecretStoreEndpoint": stack.urls["secret-store"],
		"TULE_Console_MailboxEndpoint":     stack.urls["mailbox"],
		"TULE_Console_QueuesEndpoint":      stack.urls["queues"],
	}
	if fn.skip == "" {
		env["TULE_Console_FunctionsEndpoint"] = stack.urls["functions"]
	}
	for k, v := range env {
		if err := os.Setenv(k, v); err != nil {
			return nil, "", fmt.Errorf("set %s: %w", k, err)
		}
	}
	cfg, err := app.LoadConfigFrom(
		config.NewEnvProvider(config.WithEnvSeparator("_"), config.WithEnvPrefix("TULE_")),
	)
	if err != nil {
		return nil, "", err
	}

	a, err := newConsole(cfg, filepath.Join(work, "console.log"))
	if err != nil {
		return nil, "", err
	}
	if err = a.Start(context.Background()); err != nil {
		return nil, "", fmt.Errorf("start: %w", err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", fmt.Errorf("listen: %w", err)
	}
	go func() {
		if serr := a.Server().Serve(l); serr != nil && !errors.Is(serr, http.ErrServerClosed) {
			_, _ = fmt.Fprintln(os.Stderr, "e2e: console serve:", serr)
		}
	}()
	return a, "http://" + l.Addr().String(), nil
}

// newConsole builds the console app with its log going to the file at
// path. The development logger writes to os.Stderr as it is when the app is
// built, so os.Stderr is the file for that long.
func newConsole(cfg *app.Config, path string) (*gas.App, error) {
	stack.logs = path
	logFile, err := os.Create(path) //nolint:gosec // G304: a file in the suite's own directory
	if err != nil {
		return nil, fmt.Errorf("create the log: %w", err)
	}
	stderr := os.Stderr
	os.Stderr = logFile
	a, err := app.New(cfg)
	os.Stderr = stderr
	if err != nil {
		return nil, fmt.Errorf("new app: %w", err)
	}
	return a, nil
}

// secretLog collects every secret the suite handles, which the console's
// log must never hold.
var secretLog struct {
	values []string
	mu     sync.Mutex
}

// noteSecret records s as a secret the log must not hold.
func noteSecret(s string) {
	secretLog.mu.Lock()
	defer secretLog.mu.Unlock()
	secretLog.values = append(secretLog.values, s)
}

func secretsInLogs() string {
	b, err := os.ReadFile(stack.logs)
	if err != nil {
		return "cannot read the log: " + err.Error()
	}
	if len(b) == 0 {
		return "the log is empty, so it was not captured"
	}
	secretLog.mu.Lock()
	defer secretLog.mu.Unlock()
	for _, s := range append([]string{rootSecret}, secretLog.values...) {
		if bytes.Contains(b, []byte(s)) {
			return s
		}
	}
	return ""
}

// browser returns a browser of the console, signed out.
func browser(t *testing.T) *consoletest.Browser {
	t.Helper()
	return (&consoletest.Server{URL: stack.console}).Browser(t)
}

// rootBrowser returns a browser signed in with the root key.
func rootBrowser(t *testing.T) *consoletest.Browser {
	t.Helper()
	b := browser(t)
	b.SignIn(rootKeyID, rootSecret)
	return b
}

// endpoint is the service's endpoint for the SDK clients the tests check
// with.
func endpoint(service string) awsclient.Endpoint {
	return awsclient.Endpoint{
		URL:    stack.urls[service],
		Region: region,
		HTTP:   &http.Client{Timeout: clientTimeout},
	}
}

func requireNoErr(t *testing.T, err error, what string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
}

// unique returns a name no other test uses.
func unique(prefix string) string {
	return prefix + strconv.FormatInt(time.Now().UnixNano()%1_000_000_000, 36)
}
