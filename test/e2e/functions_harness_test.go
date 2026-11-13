//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The functions section runs against a real functions service only where
// the suite can run its functions: with a functions checkout
// (TULE_E2E_FUNCTIONS_DIR, or the sibling) and a Docker daemon. The one
// function is the echo handler under testdata, wrapped in an image built
// FROM scratch, so no image is ever pulled. Without either, the functions
// tests are skipped and the section is covered by its unit tests.

// fn is the functions part of the suite.
var fn struct {
	// skip says why the functions tests do not run, "" when they do.
	skip  string
	image string
}

// startFunctions builds and starts functions when it can, and returns what
// to undo when the suite ends.
func startFunctions(work string) (func(), error) {
	src := os.Getenv("TULE_E2E_FUNCTIONS_DIR")
	if src == "" {
		src = filepath.Join("..", "..", "..", "functions")
	}
	if fn.skip = skipFunctions(src); fn.skip != "" {
		return func() {}, nil
	}

	runID := strconv.FormatInt(time.Now().UnixNano(), 36)
	fn.image = "tule-console-e2e/echo:" + runID
	if err := buildEchoImage(work); err != nil {
		return func() {}, err
	}
	undo := func() { removeEchoImage() }

	port, err := freePort()
	if err != nil {
		return undo, err
	}
	runtimePort, err := freePort()
	if err != nil {
		return undo, err
	}
	stack.urls["functions"] = "http://127.0.0.1:" + strconv.Itoa(port)

	bin, err := build(work, "functions")
	if err != nil {
		return undo, err
	}
	dir := filepath.Join(work, "functions-data")
	if err = os.MkdirAll(dir, 0o700); err != nil {
		return undo, fmt.Errorf("make the store of functions: %w", err)
	}
	p, err := start("functions", bin, dir, []string{
		"TULE_GasEnv=testing",
		"TULE_Server_Port=" + strconv.Itoa(port),
		"TULE_Functions_RuntimeAPIPort=" + strconv.Itoa(runtimePort),
		"TULE_Store_Path=" + filepath.Join(dir, "functions.db"),
		"TULE_Auth_AccessKeyID=" + rootKeyID,
		"TULE_Auth_SecretAccessKey=" + rootSecret,
		"TULE_Auth_IdentityEndpoint=" + stack.urls["identity"],
		"TULE_Functions_QueuesEndpoint=" + stack.urls["queues"],
	})
	if err != nil {
		return undo, err
	}
	undo = func() {
		p.stop()
		removeEchoImage()
	}
	return undo, p.waitReady(stack.urls["functions"])
}

// skipFunctions returns why the functions tests cannot run with the
// checkout at src, or "" when they can.
func skipFunctions(src string) string {
	//nolint:gosec // G703: the checkout the suite is told to build
	if _, err := os.Stat(filepath.Join(src, "go.mod")); err != nil {
		return "no functions checkout at " + src
	}
	if _, err := docker(context.Background(), "info"); err != nil {
		return "no Docker daemon: " + err.Error()
	}
	return ""
}

// buildEchoImage builds testdata/echo for linux on the host's architecture
// and wraps it in an image FROM scratch, never pulling.
func buildEchoImage(work string) error {
	dir := filepath.Join(work, "echo-image")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("image dir: %w", err)
	}
	//nolint:gosec // G204: go build of this suite's own testdata
	cmd := exec.Command("go", "build", "-tags", "lambda.norpc", "-trimpath",
		"-o", filepath.Join(dir, "bootstrap"), "./echo")
	cmd.Dir = "testdata"
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+runtime.GOARCH, "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("build the echo handler: %w\n%s", err, out)
	}
	dockerfile := "FROM scratch\nCOPY bootstrap /bootstrap\nENTRYPOINT [\"/bootstrap\"]\n"
	if err := os.WriteFile(
		filepath.Join(dir, "Dockerfile"),
		[]byte(dockerfile),
		0o600,
	); err != nil {
		return fmt.Errorf("write the Dockerfile: %w", err)
	}
	_, err := docker(context.Background(), "build", "--pull=false", "-q", "-t", fn.image, dir)
	return err
}

// removeEchoImage removes the image and any container left from it.
func removeEchoImage() {
	ctx := context.Background()
	ids, _ := docker(ctx, "ps", "-a", "-q", "--filter", "ancestor="+fn.image)
	if f := strings.Fields(ids); len(f) > 0 {
		_, _ = docker(ctx, append([]string{"rm", "-f"}, f...)...)
	}
	_, _ = docker(ctx, "rmi", "-f", fn.image)
}

func docker(ctx context.Context, args ...string) (string, error) {
	//nolint:gosec // G204: the docker CLI, with this suite's own arguments
	cmd := exec.CommandContext(ctx, "docker", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("docker %s: %w\n%s", strings.Join(args, " "), err, stderr.String())
	}
	return stdout.String(), nil
}

// requireFunctions skips the test when the suite runs without functions.
func requireFunctions(t *testing.T) {
	t.Helper()
	if fn.skip != "" {
		t.Skip("functions is not running: " + fn.skip)
	}
}

// hostArch is the host's architecture in Lambda's names.
func hostArch() string {
	if runtime.GOARCH == "amd64" {
		return "x86_64"
	}
	return runtime.GOARCH
}
