package awsclient_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"

	"tule.dev/console/internal/awsclient"
)

// retrieval serves a retrieval API with one message, a/b, and refuses a
// listing; got is the last request it served.
func retrieval(t *testing.T, got **http.Request) *awsclient.Signed {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*got = r.Clone(r.Context())
		switch r.URL.EscapedPath() {
		case "/_mailbox/messages/a%2Fb":
			_, _ = w.Write([]byte(`{"id":"a/b"}`))
		case "/_mailbox/messages":
			w.Header().Set("X-Amzn-ErrorType", "BadRequestException")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write(
				[]byte(`{"code":"BadRequestException","message":"limit must be 1 to 100"}`),
			)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return awsclient.NewSigned(
		awsclient.Endpoint{URL: srv.URL, Region: "eu-west-1", HTTP: srv.Client()},
		"ses",
		aws.Credentials{AccessKeyID: "AKID", SecretAccessKey: "secret"},
	)
}

func TestSignedJSON(t *testing.T) {
	var got *http.Request
	c := retrieval(t, &got)
	var out struct {
		ID string `json:"id"`
	}
	if err := c.JSON(
		t.Context(),
		http.MethodGet,
		c.URL(nil, "_mailbox", "messages", "a/b"),
		&out,
	); err != nil {
		t.Fatalf("get: %v", err)
	}
	if out.ID != "a/b" {
		t.Fatalf("decoded %+v", out)
	}
	auth := got.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=AKID/") ||
		!strings.Contains(auth, "/eu-west-1/ses/aws4_request") {
		t.Fatalf("Authorization %q", auth)
	}
	if got.Header.Get("X-Amz-Date") == "" {
		t.Fatal("the request carries no signing date")
	}
}

func TestSignedError(t *testing.T) {
	var got *http.Request
	c := retrieval(t, &got)
	var out struct{}
	err := c.JSON(
		t.Context(),
		http.MethodGet,
		c.URL(url.Values{"limit": {"0"}}, "_mailbox", "messages"),
		&out,
	)
	e, ok := awsclient.AsAPIError(err)
	if !ok || e.Status != 400 || e.Code != "BadRequestException" ||
		e.Message != "limit must be 1 to 100" {
		t.Fatalf("err %v", err)
	}
	if got.URL.RawQuery != "limit=0" {
		t.Fatalf("query %q", got.URL.RawQuery)
	}
}

func TestReady(t *testing.T) {
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/_ready" || r.Header.Get("Authorization") != "" {
			t.Errorf("probe %s with Authorization %q", r.URL.Path, r.Header.Get("Authorization"))
		}
		w.WriteHeader(status)
	}))
	defer srv.Close()
	ep := awsclient.Endpoint{URL: srv.URL, HTTP: srv.Client()}
	if r := awsclient.Ready(t.Context(), ep); r.State != "ready" {
		t.Fatalf("readiness %+v", r)
	}
	status = http.StatusServiceUnavailable
	if r := awsclient.Ready(
		t.Context(),
		ep,
	); r.State != "not ready" ||
		!strings.Contains(r.Detail, "503") {
		t.Fatalf("readiness %+v", r)
	}
	ep.URL = "http://127.0.0.1:1"
	if r := awsclient.Ready(t.Context(), ep); r.State != "unreachable" {
		t.Fatalf("readiness %+v", r)
	}
}
