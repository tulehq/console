package signin_test

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/html/atom"

	"tule.dev/console/internal/app"
	"tule.dev/console/internal/awsclient"
	"tule.dev/console/internal/consoletest"
	"tule.dev/console/internal/modules/signin"
	"tule.dev/console/internal/session"
)

func start(t *testing.T) *consoletest.Server {
	t.Helper()
	return consoletest.Start(t, app.Overrides{}, nil, "s3")
}

func TestSignInPage(t *testing.T) {
	s := start(t)
	b := s.Browser(t)
	res := b.Get("/signin")
	consoletest.RequireStatus(t, res, http.StatusOK)
	for _, name := range []string{"accessKeyId", "secretAccessKey", "sessionToken", "_csrf"} {
		if consoletest.Find(res.Doc, consoletest.ByName(name)) == nil {
			t.Fatalf("the sign-in form has no %s field", name)
		}
	}
	if res.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control %q, want no-store", res.Header.Get("Cache-Control"))
	}
	if !strings.Contains(res.Header.Get("Content-Security-Policy"), "script-src 'self'") {
		t.Fatalf("no page CSP: %q", res.Header.Get("Content-Security-Policy"))
	}
}

func TestSignInWithTheKey(t *testing.T) {
	s := start(t)
	b := s.Browser(t)
	res := b.TrySignIn(consoletest.KeyID, consoletest.Secret, "")
	consoletest.RequireStatus(t, res, http.StatusSeeOther)
	if res.Location() != "/" {
		t.Fatalf("redirect to %q, want /", res.Location())
	}

	requireSessionCookie(t, res)

	page := b.Get("/")
	consoletest.RequireStatus(t, page, http.StatusOK)
	consoletest.RequireText(t, page, consoletest.ARN, "Object store")
	if strings.Contains(string(page.Body), consoletest.KeyID) ||
		strings.Contains(string(page.Body), consoletest.Secret) {
		t.Fatal("a page carries the key")
	}
	if s.Store.Len() != 1 {
		t.Fatalf("%d sessions, want 1", s.Store.Len())
	}
}

// requireSessionCookie fails unless res sets the session cookie HttpOnly,
// SameSite=Strict, for the whole site, not Secure over plain HTTP, and
// without the key in it.
func requireSessionCookie(t *testing.T, res *consoletest.Response) {
	t.Helper()
	var cookie *http.Cookie
	for _, c := range (&http.Response{Header: res.Header}).Cookies() {
		if c.Name == session.CookieName {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("no session cookie")
	}
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/" {
		t.Fatalf("session cookie %+v, want HttpOnly, SameSite=Strict, Path=/", cookie)
	}
	if cookie.Secure {
		t.Fatal("the cookie is Secure over plain HTTP, so the browser would drop it")
	}
	if strings.Contains(cookie.Value, consoletest.KeyID) ||
		strings.Contains(cookie.Value, consoletest.Secret) {
		t.Fatal("the cookie carries the key")
	}
}

func TestSecureCookieSetting(t *testing.T) {
	s := consoletest.Start(
		t,
		app.Overrides{},
		map[string]string{"TULE_Console_SecureCookie": "true"},
		"s3",
	)
	res := s.Browser(t).TrySignIn(consoletest.KeyID, consoletest.Secret, "")
	consoletest.RequireStatus(t, res, http.StatusSeeOther)
	if !strings.Contains(res.Header.Get("Set-Cookie"), "Secure") {
		t.Fatalf("Set-Cookie %q is not Secure", res.Header.Get("Set-Cookie"))
	}
}

func TestBadKeyRefused(t *testing.T) {
	s := start(t)
	b := s.Browser(t)
	res := b.TrySignIn(consoletest.KeyID, "wrong-secret", "")
	consoletest.RequireStatus(t, res, http.StatusUnauthorized)
	consoletest.RequireText(t, res, "The key was refused")
	if strings.Contains(string(res.Body), "wrong-secret") {
		t.Fatal("the refusal echoes the secret")
	}
	if s.Store.Len() != 0 {
		t.Fatal("a refused key made a session")
	}
	consoletest.RequireStatus(t, b.Get("/s3"), http.StatusSeeOther)
}

func TestEmptyKey(t *testing.T) {
	res := start(t).Browser(t).TrySignIn("", "", "")
	consoletest.RequireStatus(t, res, http.StatusBadRequest)
}

func TestSignInNeedsTheFormToken(t *testing.T) {
	s := start(t)
	b := s.Browser(t)
	b.Get("/signin")
	res := b.PostForm("/signin", url.Values{
		"accessKeyId": {
			consoletest.KeyID,
		},
		"secretAccessKey": {consoletest.Secret},
		"_csrf":           {"forged"},
	})
	consoletest.RequireStatus(t, res, http.StatusForbidden)

	// A form token without its cookie, as another site would post it.
	other := s.Browser(t)
	res = other.PostForm("/signin", url.Values{
		"accessKeyId": {
			consoletest.KeyID,
		},
		"secretAccessKey": {consoletest.Secret},
		"_csrf":           {b.CSRF},
	})
	consoletest.RequireStatus(t, res, http.StatusForbidden)
	if s.Store.Len() != 0 {
		t.Fatal("a forged sign-in made a session")
	}
}

func TestSignInIsRateLimited(t *testing.T) {
	s := start(t)
	now := time.Now()
	s.Limiter.SetClock(func() time.Time { return now })
	b := s.Browser(t)
	for i := range 10 {
		res := b.TrySignIn(consoletest.KeyID, "wrong", "")
		if res.Status != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status %d, want 401", i+1, res.Status)
		}
	}
	res := b.TrySignIn(consoletest.KeyID, consoletest.Secret, "")
	consoletest.RequireStatus(t, res, http.StatusTooManyRequests)

	now = now.Add(7 * time.Second)
	res = b.TrySignIn(consoletest.KeyID, consoletest.Secret, "")
	consoletest.RequireStatus(t, res, http.StatusSeeOther)
}

func TestSuccessfulSignInsAreNotLimited(t *testing.T) {
	s := start(t)
	for i := range 30 {
		res := s.Browser(t).TrySignIn(consoletest.KeyID, consoletest.Secret, "")
		if res.Status != http.StatusSeeOther {
			t.Fatalf("sign-in %d: status %d", i+1, res.Status)
		}
	}
}

func TestSignedOutRedirects(t *testing.T) {
	s := start(t)
	b := s.Browser(t)

	res := b.Get("/s3/bucket?bucket=photos")
	consoletest.RequireStatus(t, res, http.StatusSeeOther)
	want := "/signin?" + url.Values{"next": {"/s3/bucket?bucket=photos"}}.Encode()
	if res.Location() != want {
		t.Fatalf("redirect to %q, want %q", res.Location(), want)
	}

	res = b.HTMX("/s3")
	consoletest.RequireStatus(t, res, http.StatusUnauthorized)
	if res.Header.Get("HX-Redirect") == "" {
		t.Fatal("an HTMX request is not sent to sign-in")
	}

	res = b.PostForm("/s3/buckets", url.Values{"bucket": {"x"}})
	consoletest.RequireStatus(t, res, http.StatusSeeOther)

	// After sign-in the browser comes back where it was going, and only to
	// a page of the console.
	res = b.TrySignIn(consoletest.KeyID, consoletest.Secret, "/s3/bucket?bucket=photos")
	if res.Location() != "/s3/bucket?bucket=photos" {
		t.Fatalf("after sign-in, redirect to %q", res.Location())
	}
	for _, next := range []string{"https://evil.example/", "//evil.example/", "/\\evil.example"} {
		res = s.Browser(t).TrySignIn(consoletest.KeyID, consoletest.Secret, next)
		if res.Location() != "/" {
			t.Fatalf("next %q: redirect to %q, want /", next, res.Location())
		}
	}
}

func TestForgedCookieRefused(t *testing.T) {
	s := start(t)
	b := s.Browser(t)
	b.SignIn(consoletest.KeyID, consoletest.Secret)
	var value string
	for _, c := range b.Cookies() {
		if c.Name == session.CookieName {
			value = c.Value
		}
	}
	id, _, _ := strings.Cut(value, ".")

	for _, v := range []string{id, id + ".forged", "x." + strings.Repeat("A", 43), ""} {
		req := s.Browser(t).Request(http.MethodGet, "/s3", http.NoBody)
		//nolint:gosec // G124: a forged cookie, as a client would send it
		req.AddCookie(&http.Cookie{Name: session.CookieName, Value: v})
		res := s.Browser(t).Do(req)
		if res.Status != http.StatusSeeOther {
			t.Fatalf("cookie %q: status %d, want a redirect to sign-in", v, res.Status)
		}
	}
}

func TestSignOut(t *testing.T) {
	s := start(t)
	b := s.Browser(t)
	b.SignIn(consoletest.KeyID, consoletest.Secret)

	// Without the token, sign-out is refused like every other post.
	res := b.PostForm("/signout", url.Values{"_csrf": {""}})
	consoletest.RequireStatus(t, res, http.StatusForbidden)

	res = b.PostForm("/signout", nil)
	consoletest.RequireStatus(t, res, http.StatusSeeOther)
	if s.Store.Len() != 0 {
		t.Fatal("sign-out left the session")
	}
	consoletest.RequireStatus(t, b.Get("/"), http.StatusSeeOther)
}

func TestSessionExpires(t *testing.T) {
	s := consoletest.Start(
		t,
		app.Overrides{},
		map[string]string{"TULE_Console_SessionTTL": "1h"},
		"s3",
	)
	now := time.Now()
	s.Store.SetClock(func() time.Time { return now })
	b := s.Browser(t)
	b.SignIn(consoletest.KeyID, consoletest.Secret)
	consoletest.RequireStatus(t, b.Get("/"), http.StatusOK)

	now = now.Add(time.Hour)
	consoletest.RequireStatus(t, b.Get("/"), http.StatusSeeOther)
	if s.Store.Len() != 0 {
		t.Fatal("the expired session was kept")
	}
}

func TestCSRF(t *testing.T) {
	s := start(t)
	b := s.Browser(t)
	b.SignIn(consoletest.KeyID, consoletest.Secret)
	other := s.Browser(t)
	other.SignIn(consoletest.KeyID, consoletest.Secret)

	tests := []struct {
		mutate func(*http.Request)
		form   url.Values
		name   string
	}{
		{name: "no token", form: url.Values{"_csrf": {""}, "bucket": {"x"}}},
		{name: "wrong token", form: url.Values{"_csrf": {"not-the-token"}, "bucket": {"x"}}},
		{name: "another session's token", form: url.Values{"_csrf": {other.CSRF}, "bucket": {"x"}}},
		{
			name: "cross-site browser request", form: url.Values{"bucket": {"x"}},
			mutate: func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") },
		},
		{
			name: "foreign origin", form: url.Values{"bucket": {"x"}},
			mutate: func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := b.FormRequest("/s3/buckets", tt.form)
			if tt.mutate != nil {
				tt.mutate(req)
			}
			res := b.Do(req)
			consoletest.RequireStatus(t, res, http.StatusForbidden)
		})
	}

	// A wrong header token is refused even with a right form token.
	req := b.FormRequest("/s3/buckets", url.Values{"bucket": {"x"}})
	req.Header.Set("X-CSRF-Token", "wrong")
	consoletest.RequireStatus(t, b.Do(req), http.StatusForbidden)
}

func TestOverviewListsSections(t *testing.T) {
	s := consoletest.Start(t, app.Overrides{}, nil, "s3", "mail", "sqs")
	b := s.Browser(t)
	b.SignIn(consoletest.KeyID, consoletest.Secret)
	res := b.Get("/")
	nav := consoletest.Find(res.Doc, consoletest.Element(atom.Nav))
	got := consoletest.Text(nav)
	for _, want := range []string{"Object store", "Mailbox", "Queues"} {
		if !strings.Contains(got, want) {
			t.Fatalf("the navigation %q lacks %s", got, want)
		}
	}
	for _, absent := range []string{"Secret store", "Accounts", "Identity", "Functions"} {
		if strings.Contains(got, absent) {
			t.Fatalf("the navigation %q shows %s, which is not configured", got, absent)
		}
	}
	consoletest.RequireStatus(t, b.Get("/secrets"), http.StatusNotFound)
	consoletest.RequireText(t, res, "ready")
}

func TestUnreachableServiceIsShown(t *testing.T) {
	s := consoletest.Start(t, app.Overrides{}, map[string]string{
		"TULE_Console_QueuesEndpoint": "http://127.0.0.1:1",
	}, "s3")
	b := s.Browser(t)
	b.SignIn(consoletest.KeyID, consoletest.Secret)
	res := b.Get("/")
	consoletest.RequireStatus(t, res, http.StatusOK)
	consoletest.RequireText(t, res, "unreachable")
}

func TestProbesArePublic(t *testing.T) {
	b := start(t).Browser(t)
	consoletest.RequireStatus(t, b.Get("/_health"), http.StatusOK)
	consoletest.RequireStatus(t, b.Get("/_ready"), http.StatusOK)
	consoletest.RequireStatus(t, b.Get("/static/console.css"), http.StatusOK)
}

// signInFrom signs in through a proxy that says the client is ip.
func signInFrom(b *consoletest.Browser, ip, secret string) *consoletest.Response {
	b.Get("/signin")
	req := b.FormRequest("/signin", url.Values{
		"accessKeyId": {consoletest.KeyID}, "secretAccessKey": {secret},
	})
	req.Header.Set("X-Forwarded-For", ip)
	return b.Do(req)
}

func TestLimitIsPerClientBehindATrustedProxy(t *testing.T) {
	s := consoletest.Start(
		t,
		app.Overrides{},
		map[string]string{"TULE_Console_TrustedProxies": "127.0.0.1/32"},
		"s3",
	)
	b := s.Browser(t)
	for range 10 {
		consoletest.RequireStatus(
			t,
			signInFrom(b, "198.51.100.7", "wrong"),
			http.StatusUnauthorized,
		)
	}
	consoletest.RequireStatus(
		t,
		signInFrom(b, "198.51.100.7", consoletest.Secret),
		http.StatusTooManyRequests,
	)
	// Another client behind the same proxy is not locked out.
	consoletest.RequireStatus(
		t,
		signInFrom(s.Browser(t), "203.0.113.20", consoletest.Secret),
		http.StatusSeeOther,
	)
}

func TestForwardedForIgnoredWithoutTrustedProxies(t *testing.T) {
	s := start(t)
	b := s.Browser(t)
	for i := range 10 {
		consoletest.RequireStatus(
			t,
			signInFrom(b, "198.51.100."+strconv.Itoa(i), "wrong"),
			http.StatusUnauthorized,
		)
	}
	// A client cannot escape the limit by naming another address.
	consoletest.RequireStatus(
		t,
		signInFrom(b, "203.0.113.20", consoletest.Secret),
		http.StatusTooManyRequests,
	)
}

func TestSessionCapRefusesSignIn(t *testing.T) {
	s := consoletest.Start(
		t,
		app.Overrides{},
		map[string]string{"TULE_Console_MaxSessions": "2"},
		"s3",
	)
	s.Browser(t).SignIn(consoletest.KeyID, consoletest.Secret)
	s.Browser(t).SignIn(consoletest.KeyID, consoletest.Secret)
	res := s.Browser(t).TrySignIn(consoletest.KeyID, consoletest.Secret, "")
	consoletest.RequireStatus(t, res, http.StatusServiceUnavailable)
	consoletest.RequireText(t, res, "The console holds as many sessions as it allows")
	if s.Store.Len() != 2 {
		t.Fatalf("%d sessions, want the 2 there were", s.Store.Len())
	}
}

func TestPerKeyCapEndsTheOldestSession(t *testing.T) {
	s := consoletest.Start(
		t,
		app.Overrides{},
		map[string]string{"TULE_Console_MaxSessionsPerKey": "2"},
		"s3",
	)
	first := s.Browser(t)
	first.SignIn(consoletest.KeyID, consoletest.Secret)
	s.Browser(t).SignIn(consoletest.KeyID, consoletest.Secret)
	s.Browser(t).SignIn(consoletest.KeyID, consoletest.Secret)
	consoletest.RequireStatus(t, first.Get("/"), http.StatusSeeOther)
	if s.Store.Len() != 2 {
		t.Fatalf("%d sessions, want 2", s.Store.Len())
	}
}

func TestSigningInAgainEndsTheOldSession(t *testing.T) {
	s := start(t)
	b := s.Browser(t)
	b.SignIn(consoletest.KeyID, consoletest.Secret)
	var old string
	for _, c := range b.Cookies() {
		if c.Name == session.CookieName {
			old = c.Value
		}
	}
	// The sign-in page sends a signed-in browser away, so the second
	// sign-in posts the form directly, as a second tab would.
	other := s.Browser(t)
	other.Get("/signin")
	req := other.FormRequest("/signin", url.Values{
		"accessKeyId": {consoletest.KeyID}, "secretAccessKey": {consoletest.Secret},
	})
	//nolint:gosec // G124: the cookie as the browser sends it back
	req.AddCookie(&http.Cookie{Name: session.CookieName, Value: old})
	consoletest.RequireStatus(t, other.Do(req), http.StatusSeeOther)
	if s.Store.Lookup(old) != nil {
		t.Fatal("signing in again kept the old session")
	}
	if s.Store.Len() != 1 {
		t.Fatalf("%d sessions, want 1", s.Store.Len())
	}
}

func TestUnreachableVerifierShowsNoDetail(t *testing.T) {
	dead := awsclient.Endpoint{
		URL:    "http://127.0.0.1:1",
		Region: "us-east-1",
		HTTP:   http.DefaultClient,
	}
	v, err := signin.NewVerifier(signin.Endpoints{ObjectStore: &dead})
	if err != nil {
		t.Fatal(err)
	}
	s := consoletest.Start(t, app.Overrides{Verifier: v}, nil, "s3")
	res := s.Browser(t).TrySignIn(consoletest.KeyID, consoletest.Secret, "")
	consoletest.RequireStatus(t, res, http.StatusBadGateway)
	consoletest.RequireText(t, res, "The key could not be verified: object-store is unreachable.")
	for _, detail := range []string{"127.0.0.1", "dial", "ListBuckets", "operation error"} {
		if strings.Contains(string(res.Body), detail) {
			t.Fatalf("the sign-in page shows %q: %s", detail, consoletest.Text(res.Doc))
		}
	}
}
