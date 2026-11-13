package session_test

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"

	"tule.dev/console/internal/session"
)

var creds = aws.Credentials{
	AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
	SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	SessionToken:    "token-value",
}

// limits are roomy enough that no test but the caps' own reaches them.
var limits = session.Limits{Max: 1000, PerKey: 100}

func newStore(t *testing.T, ttl time.Duration) (*session.Store, *time.Time) {
	t.Helper()
	s, err := session.NewStore(ttl, false, limits)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	now := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)
	s.SetClock(func() time.Time { return now })
	return s, &now
}

// create starts a session on s, failing the test if it cannot.
func create(t *testing.T, s *session.Store, p session.Principal) (*session.Session, string) {
	t.Helper()
	sess, value, err := s.Create(creds, p)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	return sess, value
}

func TestCreateAndLookup(t *testing.T) {
	s, _ := newStore(t, time.Hour)
	sess, value, err := s.Create(creds, session.Principal{ARN: "arn", KeyHint: "MPLE"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if strings.Contains(value, creds.AccessKeyID) ||
		strings.Contains(value, creds.SecretAccessKey) {
		t.Fatal("the cookie value carries the key")
	}
	got := s.Lookup(value)
	if got != sess || got.Credentials() != creds || got.Principal().ARN != "arn" {
		t.Fatal("lookup did not return the session with its key")
	}
	if len(sess.CSRFToken()) < 40 {
		t.Fatalf("CSRF token %q is short", sess.CSRFToken())
	}

	other, value2 := create(t, s, session.Principal{})
	if value2 == value || other.CSRFToken() == sess.CSRFToken() {
		t.Fatal("two sessions share an ID or a token")
	}
}

func TestLookupRefusesForgeries(t *testing.T) {
	s, _ := newStore(t, time.Hour)
	_, value := create(t, s, session.Principal{})
	id, mac, _ := strings.Cut(value, ".")

	other, err := session.NewStore(time.Hour, false, limits)
	if err != nil {
		t.Fatal(err)
	}
	_, foreign := create(t, other, session.Principal{})

	for _, v := range []string{
		"", id, id + ".", "." + mac, id + "." + mac[:len(mac)-1], id + "x." + mac,
		strings.ToUpper(id) + "." + mac, foreign,
	} {
		if s.Lookup(v) != nil {
			t.Fatalf("lookup accepted %q", v)
		}
	}
}

func TestExpiry(t *testing.T) {
	s, now := newStore(t, time.Hour)
	_, value := create(t, s, session.Principal{})
	*now = now.Add(59 * time.Minute)
	if s.Lookup(value) == nil {
		t.Fatal("the session expired early")
	}
	*now = now.Add(time.Minute)
	if s.Lookup(value) != nil {
		t.Fatal("the session outlived its TTL")
	}
	if s.Len() != 0 {
		t.Fatal("the expired session was kept")
	}
}

func TestSweep(t *testing.T) {
	s, now := newStore(t, time.Hour)
	create(t, s, session.Principal{})
	*now = now.Add(30 * time.Minute)
	_, fresh := create(t, s, session.Principal{})
	*now = now.Add(31 * time.Minute)
	s.Sweep()
	if s.Len() != 1 || s.Lookup(fresh) == nil {
		t.Fatalf("after sweep %d sessions, want the fresh one", s.Len())
	}
}

func TestDeleteAndClose(t *testing.T) {
	s, _ := newStore(t, time.Hour)
	sess, value := create(t, s, session.Principal{})
	s.Delete(sess)
	if s.Lookup(value) != nil {
		t.Fatal("a deleted session is found")
	}
	if err := s.Init(t.Context()); err != nil {
		t.Fatalf("init: %v", err)
	}
	_, value = create(t, s, session.Principal{})
	if err := s.Close(t.Context()); err != nil {
		t.Fatalf("close: %v", err)
	}
	if s.Lookup(value) != nil {
		t.Fatal("close kept a session")
	}
}

func TestCSRF(t *testing.T) {
	s, _ := newStore(t, time.Hour)
	sess, _ := create(t, s, session.Principal{})
	if !sess.CheckCSRF(sess.CSRFToken()) {
		t.Fatal("the session's token is refused")
	}
	for _, bad := range []string{"", "x", sess.CSRFToken() + "x", sess.CSRFToken()[1:]} {
		if sess.CheckCSRF(bad) {
			t.Fatalf("token %q accepted", bad)
		}
	}
}

func TestFlash(t *testing.T) {
	s, _ := newStore(t, time.Hour)
	sess, _ := create(t, s, session.Principal{})
	sess.SetFlash("ok", "first")
	sess.SetFlash("error", "second")
	if f := sess.PopFlash(); f == nil || f.Message != "second" || f.Kind != "error" {
		t.Fatalf("flash %+v", f)
	}
	if sess.PopFlash() != nil {
		t.Fatal("a flash showed twice")
	}
}

func TestCookie(t *testing.T) {
	s, _ := newStore(t, 2*time.Hour)
	c := s.Cookie(httptest.NewRequest(http.MethodGet, "/", nil), "v")
	if c.Name != session.CookieName || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode ||
		c.Path != "/" || c.MaxAge != 7200 || c.Secure {
		t.Fatalf("cookie %+v", c)
	}
	if e := s.ExpiredCookie(
		httptest.NewRequest(http.MethodGet, "/", nil),
	); e.MaxAge != -1 ||
		e.Value != "" {
		t.Fatalf("expired cookie %+v", e)
	}
}

func TestSecureCookie(t *testing.T) {
	s, _ := newStore(t, time.Hour)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.TLS = &tls.ConnectionState{}
	if !s.Cookie(r, "v").Secure {
		t.Fatal("a cookie over TLS is not Secure")
	}
	secure, err := session.NewStore(time.Hour, true, limits)
	if err != nil {
		t.Fatal(err)
	}
	if !secure.Cookie(httptest.NewRequest(http.MethodGet, "/", nil), "v").Secure {
		t.Fatal("the Secure setting is ignored")
	}
}

func TestFormattingHidesTheKey(t *testing.T) {
	s, _ := newStore(t, time.Hour)
	sess, _ := create(t, s, session.Principal{KeyHint: "MPLE"})
	for _, f := range []string{"%v", "%+v", "%#v", "%s"} {
		out := fmt.Sprintf(f, sess)
		if strings.Contains(out, creds.SecretAccessKey) ||
			strings.Contains(out, creds.AccessKeyID) ||
			strings.Contains(out, creds.SessionToken) ||
			strings.Contains(out, sess.CSRFToken()) {
			t.Fatalf("%s of a session prints %q", f, out)
		}
	}
}

func newLimited(t *testing.T, l session.Limits) (*session.Store, *time.Time) {
	t.Helper()
	s, err := session.NewStore(time.Hour, false, l)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	now := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)
	s.SetClock(func() time.Time { return now })
	return s, &now
}

func keyed(id string) aws.Credentials {
	return aws.Credentials{AccessKeyID: id, SecretAccessKey: "s"}
}

func TestPerKeyCapEndsTheKeysOldest(t *testing.T) {
	s, now := newLimited(t, session.Limits{Max: 100, PerKey: 2})
	_, first, _ := s.Create(keyed("A"), session.Principal{})
	*now = now.Add(time.Second)
	_, second, _ := s.Create(keyed("A"), session.Principal{})
	_, other, _ := s.Create(keyed("B"), session.Principal{})
	_, third, err := s.Create(keyed("A"), session.Principal{})
	if err != nil {
		t.Fatalf("create past the per-key cap: %v", err)
	}
	if s.Lookup(first) != nil {
		t.Fatal("the key's oldest session outlived the per-key cap")
	}
	for _, v := range []string{second, third, other} {
		if s.Lookup(v) == nil {
			t.Fatal("a session that is not the key's oldest was ended")
		}
	}
	if s.Len() != 3 {
		t.Fatalf("%d sessions, want 3", s.Len())
	}
}

func TestGlobalCapRefuses(t *testing.T) {
	s, now := newLimited(t, session.Limits{Max: 2, PerKey: 5})
	_, a, _ := s.Create(keyed("A"), session.Principal{})
	_, b, _ := s.Create(keyed("B"), session.Principal{})
	if _, _, err := s.Create(keyed("C"), session.Principal{}); !errors.Is(err, session.ErrFull) {
		t.Fatalf("err %v, want ErrFull", err)
	}
	if s.Lookup(a) == nil || s.Lookup(b) == nil {
		t.Fatal("a refused sign-in ended another session")
	}

	// Expired sessions make room.
	*now = now.Add(2 * time.Hour)
	if _, _, err := s.Create(keyed("C"), session.Principal{}); err != nil {
		t.Fatalf("create after the others expired: %v", err)
	}
}

func TestDeleteKeepsTheKeyIndex(t *testing.T) {
	s, _ := newLimited(t, session.Limits{Max: 100, PerKey: 1})
	sess, _, _ := s.Create(keyed("A"), session.Principal{})
	s.Delete(sess)
	s.Delete(sess) // a second delete changes nothing
	_, v, err := s.Create(keyed("A"), session.Principal{})
	if err != nil || s.Lookup(v) == nil || s.Len() != 1 {
		t.Fatalf("after delete: err %v, %d sessions", err, s.Len())
	}
}

func TestUploadSlots(t *testing.T) {
	s, _ := newStore(t, time.Hour)
	sess, _ := create(t, s, session.Principal{})
	for i := range 2 {
		if !sess.StartUpload(2) {
			t.Fatalf("upload %d of 2 was refused", i+1)
		}
	}
	if sess.StartUpload(2) {
		t.Fatal("a third upload at once was allowed")
	}
	sess.DoneUpload()
	if !sess.StartUpload(2) {
		t.Fatal("a finished upload did not free its slot")
	}
}

func TestFormToken(t *testing.T) {
	s, now := newStore(t, time.Hour)
	token, err := s.NewFormToken()
	if err != nil {
		t.Fatal(err)
	}
	if !s.ValidFormToken(token) {
		t.Fatal("a fresh form token is refused")
	}
	other, err := session.NewStore(time.Hour, false, limits)
	if err != nil {
		t.Fatal(err)
	}
	foreign, _ := other.NewFormToken()
	_, cookie := create(t, s, session.Principal{})
	i := strings.LastIndexByte(token, '.')
	for _, bad := range []string{"", "x", token + "x", token[:i] + ".", "a.99999999999." + token[i+1:], foreign, cookie} {
		if s.ValidFormToken(bad) {
			t.Fatalf("form token %q accepted", bad)
		}
	}
	*now = now.Add(session.FormTokenTTL)
	if s.ValidFormToken(token) {
		t.Fatal("an expired form token is accepted")
	}
}
