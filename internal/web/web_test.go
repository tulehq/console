package web_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"tule.dev/console/internal/awsclient"
	"tule.dev/console/internal/web"
)

// htmxSHA256 is the checksum third_party/htmx/README.md records for the
// served htmx.min.js, 2.0.11.
const htmxSHA256 = "d6fdc75f204e6bdefa99b69bf1e6d4ac69b8a364f77929f45c13476b4000f717"

func TestVendoredHTMX(t *testing.T) {
	f, err := web.Static().Open("htmx.min.js")
	if err != nil {
		t.Fatalf("open htmx.min.js: %v", err)
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		t.Fatalf("read htmx.min.js: %v", err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != htmxSHA256 {
		t.Fatalf("htmx.min.js has SHA-256 %s, want the recorded %s", got, htmxSHA256)
	}
}

func TestStaticHoldsOnlyAssets(t *testing.T) {
	var names []string
	err := fs.WalkDir(web.Static(), ".", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			names = append(names, p)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(names, ",") != "console.css,console.js,htmx.min.js" {
		t.Fatalf("static files %v", names)
	}
}

func responseError(status int, err error) error {
	return &smithy.OperationError{ServiceID: "S3", OperationName: "X", Err: &awshttp.ResponseError{
		ResponseError: &smithyhttp.ResponseError{
			Response: &smithyhttp.Response{Response: &http.Response{StatusCode: status}},
			Err:      err,
		},
	}}
}

func TestDescribe(t *testing.T) {
	api := &smithy.GenericAPIError{Code: "NoSuchKey", Message: "The specified key does not exist."}
	tests := []struct {
		err    error
		code   string
		msg    string
		status int
	}{
		{responseError(404, api), "NoSuchKey", "The specified key does not exist.", 404},
		{
			responseError(403, &smithy.GenericAPIError{Code: "InvalidAccessKeyId"}),
			"InvalidAccessKeyId",
			"InvalidAccessKeyId",
			403,
		},
		{responseError(401, &smithy.GenericAPIError{Code: "X", Message: "m"}), "X", "m", 403},
		{
			responseError(500, &smithy.GenericAPIError{Code: "InternalError", Message: "boom"}),
			"InternalError",
			"boom",
			502,
		},
		{
			&awsclient.APIError{Status: 404, Code: "NotFoundException", Message: "gone"},
			"NotFoundException",
			"gone",
			404,
		},
		{fmt.Errorf("wrap: %w", &awsclient.APIError{Status: 503}), "", "Service Unavailable", 502},
		{&web.BadInput{Message: "bad"}, "", "bad", 400},
		{&web.NotFoundError{Message: "none"}, "", "none", 404},
		{context.DeadlineExceeded, "", "The service did not answer in time.", 504},
		{
			errors.New("dial tcp: connection refused"),
			"",
			"The service could not be reached: dial tcp: connection refused",
			502,
		},
	}
	for _, tt := range tests {
		got := web.Describe(tt.err)
		if got.Code != tt.code || got.Message != tt.msg || got.Status != tt.status {
			t.Errorf(
				"Describe(%v) = %+v, want code %q message %q status %d",
				tt.err,
				got,
				tt.code,
				tt.msg,
				tt.status,
			)
		}
	}
}

func TestLink(t *testing.T) {
	for _, tt := range []struct {
		want string
		kv   []string
	}{
		{"/s3", nil},
		{"/s3", []string{"prefix", ""}},
		{"/s3/bucket?bucket=a&prefix=b%2Fc%2F", []string{"bucket", "a", "prefix", "b/c/"}},
		{"/x?k=%22%3E%3Cscript%3E", []string{"k", `"><script>`}},
	} {
		if got := web.Link(strings.Split(tt.want, "?")[0], tt.kv...); got != tt.want {
			t.Errorf("Link(%v) = %q, want %q", tt.kv, got, tt.want)
		}
	}
}

func TestLocalPath(t *testing.T) {
	for p, want := range map[string]bool{
		"/": true, "/s3/bucket?bucket=a": true,
		"": false, "s3": false, "//evil.example": false, "/\\evil.example": false,
		"https://evil.example": false, "/a\nb": false, "/a\\b": false,
	} {
		if got := web.LocalPath(p); got != want {
			t.Errorf("LocalPath(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestLimiter(t *testing.T) {
	l := web.NewLimiter(3, time.Second, 100, nil)
	now := time.Unix(0, 0)
	l.SetClock(func() time.Time { return now })
	for i := range 3 {
		if l.BlockedKey("a") {
			t.Fatalf("blocked after %d failures", i)
		}
		l.FailKey("a")
	}
	if !l.BlockedKey("a") {
		t.Fatal("not blocked after three failures")
	}
	if l.BlockedKey("b") {
		t.Fatal("another address shares the limit")
	}
	now = now.Add(time.Second)
	if l.BlockedKey("a") {
		t.Fatal("no failure was earned back after the interval")
	}
	l.FailKey("a")
	if !l.BlockedKey("a") {
		t.Fatal("more than one failure was earned back per interval")
	}
}

func TestAttachmentHeaders(t *testing.T) {
	h := http.Header{}
	web.AttachmentHeaders(h, "../evil\"\r\nname.html", "text/html")
	cd := h.Get("Content-Disposition")
	if !strings.HasPrefix(cd, "attachment;") || strings.ContainsAny(cd, "\r\n") ||
		strings.Contains(cd, "/") {
		t.Fatalf("Content-Disposition %q", cd)
	}
	if !strings.Contains(h.Get("Content-Security-Policy"), "sandbox") ||
		h.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("headers %v", h)
	}
	web.AttachmentHeaders(h, "", "not a type")
	if h.Get("Content-Type") != "application/octet-stream" ||
		!strings.Contains(h.Get("Content-Disposition"), "download") {
		t.Fatalf("headers %v", h)
	}
}

func TestFormat(t *testing.T) {
	for n, want := range map[int64]string{0: "0 B", 1023: "1023 B", 1024: "1.0 KiB", 5 << 20: "5.0 MiB"} {
		if got := web.FormatBytes(n); got != want {
			t.Errorf("FormatBytes(%d) = %q, want %q", n, got, want)
		}
	}
	if web.FormatTime(time.Time{}) != "" || web.FormatTimePtr(nil) != "" {
		t.Error("the zero time is not blank")
	}
	at := time.Date(2026, 11, 13, 12, 0, 0, 0, time.FixedZone("x", 3600))
	if got := web.FormatTime(at); got != "2026-11-13 11:00:00 UTC" {
		t.Errorf("FormatTime = %q", got)
	}
}

func request(peer string, xff ...string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/signin", nil)
	r.RemoteAddr = peer
	for _, h := range xff {
		r.Header.Add("X-Forwarded-For", h)
	}
	return r
}

func TestClientIP(t *testing.T) {
	proxies, err := web.ParsePrefixes("10.0.0.0/8, 192.168.1.5, fd00::/8")
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		r       *http.Request
		name    string
		want    string
		trusted []netip.Prefix
	}{
		{name: "no proxies: the header is ignored", r: request("203.0.113.9:5000", "1.2.3.4"), want: "203.0.113.9"},
		{
			name: "an untrusted peer's header is ignored", r: request("203.0.113.9:5000", "1.2.3.4"),
			trusted: proxies, want: "203.0.113.9",
		},
		{
			name: "a trusted peer names the client", r: request("10.1.1.1:5000", "1.2.3.4"),
			trusted: proxies, want: "1.2.3.4",
		},
		{
			name: "the rightmost untrusted hop", r: request("10.1.1.1:5000", "6.6.6.6, 1.2.3.4, 192.168.1.5"),
			trusted: proxies, want: "1.2.3.4",
		},
		{
			name: "hops across headers", r: request("10.1.1.1:5000", "6.6.6.6", "1.2.3.4, 10.9.9.9"),
			trusted: proxies, want: "1.2.3.4",
		},
		{
			name: "a junk hop stops at the trusted one before it", r: request("10.1.1.1:5000", "1.2.3.4, junk, 10.2.2.2"),
			trusted: proxies, want: "10.2.2.2",
		},
		{name: "no header from a trusted peer", r: request("10.1.1.1:5000"), trusted: proxies, want: "10.1.1.1"},
		{name: "IPv4-mapped peer", r: request("[::ffff:10.1.1.1]:5000", "1.2.3.4"), trusted: proxies, want: "1.2.3.4"},
		{name: "IPv6 proxy", r: request("[fd00::1]:5000", "2001:db8::7"), trusted: proxies, want: "2001:db8::7"},
	} {
		if got := web.ClientIP(tt.r, tt.trusted).String(); got != tt.want {
			t.Errorf("%s: ClientIP = %s, want %s", tt.name, got, tt.want)
		}
	}
}

func TestParsePrefixesRefusesJunk(t *testing.T) {
	if _, err := web.ParsePrefixes("10.0.0.0/8, not-an-address"); err == nil {
		t.Fatal("a junk prefix was accepted")
	}
	if p, err := web.ParsePrefixes(""); err != nil || len(p) != 0 {
		t.Fatalf("empty: %v %v", p, err)
	}
}

func TestIPv6ClientsShareTheirSlash64(t *testing.T) {
	l := web.NewLimiter(2, time.Hour, 100, nil)
	l.Fail(request("[2001:db8:1:2::1]:1"))
	l.Fail(request("[2001:db8:1:2:ffff::9]:1"))
	if !l.Blocked(request("[2001:db8:1:2::abcd]:1")) {
		t.Fatal("addresses of one /64 do not share a limit")
	}
	if l.Blocked(request("[2001:db8:1:3::1]:1")) {
		t.Fatal("another /64 shares the limit")
	}
}

func TestLimiterBehindATrustedProxy(t *testing.T) {
	proxies, _ := web.ParsePrefixes("127.0.0.1")
	l := web.NewLimiter(2, time.Hour, 100, proxies)
	l.Fail(request("127.0.0.1:1", "1.1.1.1"))
	l.Fail(request("127.0.0.1:1", "1.1.1.1"))
	if !l.Blocked(request("127.0.0.1:1", "1.1.1.1")) {
		t.Fatal("the failing client is not blocked")
	}
	if l.Blocked(request("127.0.0.1:1", "2.2.2.2")) {
		t.Fatal("another client behind the proxy is blocked: the limit is global")
	}
}

func TestLimiterForgetsTheLeastRecentlyUsed(t *testing.T) {
	l := web.NewLimiter(1, time.Hour, 3, nil)
	for _, k := range []string{"a", "b", "c"} {
		l.FailKey(k)
	}
	l.FailKey("a") // a is now the most recent
	l.FailKey("d") // b, the least recent, goes
	if l.Len() != 3 {
		t.Fatalf("%d clients kept, want 3", l.Len())
	}
	if l.BlockedKey("b") {
		t.Fatal("the least recently used client was kept")
	}
	if !l.BlockedKey("a") || !l.BlockedKey("c") || !l.BlockedKey("d") {
		t.Fatal("a recent client was forgotten")
	}
}
