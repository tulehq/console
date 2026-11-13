// Package consoletest runs the console for tests: the real app, over a
// real listener, with the services replaced by the caller's fakes, and a
// browser that drives it over HTTP and parses its pages with
// golang.org/x/net/html. No real browser is involved.
package consoletest

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/gasmod/gas"
	"github.com/gasmod/gas/config"

	"tule.dev/console/internal/app"
	"tule.dev/console/internal/modules/signin"
	"tule.dev/console/internal/session"
	"tule.dev/console/internal/web"
)

// The key the fake verifier accepts, and who it says the key is: the AWS
// documentation's example key.
//
//nolint:gosec // G101: the documentation's example key, not a credential
const (
	KeyID     = "AKIAIOSFODNN7EXAMPLE"
	Secret    = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	ARN       = "arn:aws:iam::000000000000:root"
	AccountID = "000000000000"
)

// AcceptTestKey is a verifier that accepts KeyID with Secret, and refuses
// every other key.
func AcceptTestKey(_ context.Context, creds aws.Credentials) (session.Principal, error) {
	if creds.AccessKeyID == KeyID && creds.SecretAccessKey == Secret {
		return session.Principal{ARN: ARN, Account: AccountID, KeyHint: "MPLE"}, nil
	}
	return session.Principal{}, signin.ErrRefused
}

// Server is a running console.
type Server struct {
	app     *gas.App
	served  chan error
	Store   *session.Store
	Limiter *web.Limiter
	// Ready is the stub every section's endpoint points at; it answers
	// /_ready with 200.
	Ready *httptest.Server
	URL   string
}

// Start runs the console with the sections named in sections ("s3",
// "secrets", ...) configured, each pointed at a stub that answers /_ready,
// and the overrides o. A nil o.Verifier accepts the test key. env adds or
// replaces TULE_ variables.
func Start(t *testing.T, o app.Overrides, env map[string]string, sections ...string) *Server {
	t.Helper()

	s := &Server{served: make(chan error, 1)}
	s.Ready = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/_ready" {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(s.Ready.Close)

	configure(t, s.Ready.URL, env, sections)

	cfg, err := app.LoadConfigFrom(config.NewEnvProvider(
		config.WithEnvSeparator("_"),
		config.WithEnvPrefix("TULE_"),
	))
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if o.Verifier == nil {
		o.Verifier = AcceptTestKey
	}
	o.Store = func(st *session.Store) { s.Store = st }
	o.Limiter = func(l *web.Limiter) { s.Limiter = l }
	a, err := app.NewWith(cfg, o)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	if err = a.Start(context.Background()); err != nil {
		t.Fatalf("start app: %v", err)
	}
	s.app = a

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s.URL = "http://" + l.Addr().String()
	go func() { s.served <- a.Server().Serve(l) }()
	t.Cleanup(func() { s.stop(t) })
	return s
}

// configure sets the TULE_ variables of a console with sections pointed at
// readyURL, and env over them.
func configure(t *testing.T, readyURL string, env map[string]string, sections []string) {
	t.Helper()
	t.Setenv("TULE_GasEnv", "testing")
	names := map[string]string{
		"s3":       "ObjectStoreEndpoint",
		"secrets":  "SecretStoreEndpoint",
		"accounts": "AccountsEndpoint",
		"iam":      "IdentityEndpoint",
		"mail":     "MailboxEndpoint",
		"sqs":      "QueuesEndpoint",
		"lambda":   "FunctionsEndpoint",
	}
	for _, key := range sections {
		name, ok := names[key]
		if !ok {
			t.Fatalf("no section %q", key)
		}
		t.Setenv("TULE_Console_"+name, readyURL)
	}
	for k, v := range env {
		t.Setenv(k, v)
	}
}

func (s *Server) stop(t *testing.T) {
	t.Helper()
	if err := s.app.Stop(context.Background()); err != nil {
		t.Errorf("stop app: %v", err)
	}
	select {
	case err := <-s.served:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("serve: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Error("serve did not return after shutdown")
	}
}
