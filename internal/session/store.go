// Package session keeps the signed-in sessions of the console in memory.
//
// A session holds the credentials it was signed in with, server-side only.
// The browser holds an opaque cookie: a random session ID and an HMAC of it
// under a key made when the store is, so a cookie cannot be forged and a
// restart, which makes a new key and an empty store, signs everyone out.
// Each session carries its own CSRF token, which every state-changing
// request must present.
package session

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// CookieName is the name of the session cookie.
const CookieName = "tule_console_session"

// sweepInterval is how often expired sessions are dropped from memory.
// Lookup refuses an expired session at once whatever the sweep.
const sweepInterval = time.Minute

// Principal is who a session is signed in as, for display: the ARN and
// account the key resolved to when the console could ask, and the last
// four characters of the access key ID, which identify the key to its
// owner without being a credential.
type Principal struct {
	ARN     string
	Account string
	KeyHint string
}

// Flash is a one-time message shown on the next page a session renders.
type Flash struct {
	Kind    string // "ok" or "error"
	Message string
}

// Session is one signed-in session. Its credentials never leave the
// server: there is no method that formats them, and Credentials returns a
// copy for signing.
type Session struct {
	creds     aws.Credentials
	expires   time.Time
	flash     *Flash
	principal Principal
	id        string
	csrf      string
	uploads   int
	mu        sync.Mutex
}

// StartUpload takes one of the session's max upload slots, and reports
// whether there was one free. Each upload holds a part of the file in
// memory, so a session's uploads at once are bounded. DoneUpload gives the
// slot back.
func (s *Session) StartUpload(maxUploads int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.uploads >= maxUploads {
		return false
	}
	s.uploads++
	return true
}

// DoneUpload gives back the slot StartUpload took.
func (s *Session) DoneUpload() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.uploads--
}

// Credentials returns the credentials to sign the session's requests with.
func (s *Session) Credentials() aws.Credentials {
	return s.creds
}

// Principal returns who the session is signed in as.
func (s *Session) Principal() Principal {
	return s.principal
}

// CSRFToken returns the session's CSRF token, which every form and HTMX
// request of the session carries.
func (s *Session) CSRFToken() string {
	return s.csrf
}

// CheckCSRF reports whether token is the session's CSRF token, compared in
// constant time.
func (s *Session) CheckCSRF(token string) bool {
	return token != "" && subtle.ConstantTimeCompare([]byte(token), []byte(s.csrf)) == 1
}

// SetFlash records a message for the next page the session renders,
// replacing one not yet shown.
func (s *Session) SetFlash(kind, message string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flash = &Flash{Kind: kind, Message: message}
}

// PopFlash returns the message recorded for this page, or nil, and forgets
// it.
func (s *Session) PopFlash() *Flash {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.flash
	s.flash = nil
	return f
}

// String names no credential, so a session printed by mistake shows
// nothing that signs.
func (s *Session) String() string {
	return "session(" + s.principal.KeyHint + ")"
}

// GoString is String, for %#v.
func (s *Session) GoString() string {
	return s.String()
}

// Limits bound the sessions a store holds: Max in all, PerKey for one
// access key.
type Limits struct {
	Max    int
	PerKey int
}

// ErrFull is returned by Create when the store holds Limits.Max live
// sessions.
var ErrFull = errors.New("session: the console holds as many sessions as it allows")

// Store holds the sessions. It implements gas.Service: Init starts the
// sweep of expired sessions and Close stops it and drops every session.
//
// Past Limits.PerKey sessions of one access key, a new one ends that key's
// oldest. At Limits.Max sessions, expired ones are dropped first, and when
// none is, a new session is refused with ErrFull rather than ending
// someone else's.
type Store struct {
	now      func() time.Time
	sessions map[string]*Session
	byKey    map[string][]*Session // oldest first
	stop     chan struct{}
	done     chan struct{}
	key      []byte
	ttl      time.Duration
	limits   Limits
	secure   bool
	mu       sync.Mutex
}

// NewStore returns a store whose sessions last ttl from sign-in. With
// secure set, the cookie is marked Secure whatever the connection; it is
// marked so on a TLS connection anyway.
func NewStore(ttl time.Duration, secure bool, limits Limits) (*Store, error) {
	if ttl <= 0 {
		return nil, errors.New("session: ttl must be positive")
	}
	if limits.Max < 1 || limits.PerKey < 1 {
		return nil, errors.New("session: limits must be at least 1")
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("session: make the cookie key: %w", err)
	}
	return &Store{
		now:      time.Now,
		sessions: make(map[string]*Session),
		byKey:    make(map[string][]*Session),
		limits:   limits,
		key:      key,
		ttl:      ttl,
		secure:   secure,
	}, nil
}

// SetClock replaces the store's clock, for tests of expiry.
func (s *Store) SetClock(now func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = now
}

// Name identifies the store to gas.
func (*Store) Name() string { return "tule/session" }

// Init starts the sweep of expired sessions.
func (s *Store) Init(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stop != nil {
		return errors.New("session: store already initialized")
	}
	s.stop, s.done = make(chan struct{}), make(chan struct{})
	go s.sweepLoop(s.stop, s.done)
	return nil
}

// Close stops the sweep and drops every session.
func (s *Store) Close(context.Context) error {
	s.mu.Lock()
	stop, done := s.stop, s.done
	s.stop, s.done = nil, nil
	clear(s.sessions)
	clear(s.byKey)
	s.mu.Unlock()
	if stop != nil {
		close(stop)
		<-done
	}
	return nil
}

func (s *Store) sweepLoop(stop <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	t := time.NewTicker(sweepInterval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			s.Sweep()
		}
	}
}

// Sweep drops every expired session.
func (s *Store) Sweep() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
}

func (s *Store) sweepLocked() {
	now := s.now()
	for _, sess := range s.sessions {
		if !now.Before(sess.expires) {
			s.removeLocked(sess)
		}
	}
}

// removeLocked drops sess from the store's indexes.
func (s *Store) removeLocked(sess *Session) {
	delete(s.sessions, sess.id)
	k := sess.creds.AccessKeyID
	list := s.byKey[k]
	for i, x := range list {
		if x == sess {
			list = append(list[:i:i], list[i+1:]...)
			break
		}
	}
	if len(list) == 0 {
		delete(s.byKey, k)
	} else {
		s.byKey[k] = list
	}
}

// Len returns the number of sessions held, expired ones not yet swept
// included.
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

// Create starts a session for creds, signed in as principal, and returns
// it with the cookie value that names it.
func (s *Store) Create(creds aws.Credentials, principal Principal) (*Session, string, error) {
	id, err := randomToken()
	if err != nil {
		return nil, "", err
	}
	csrf, err := randomToken()
	if err != nil {
		return nil, "", err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	k := creds.AccessKeyID
	for len(s.byKey[k]) >= s.limits.PerKey {
		s.removeLocked(s.byKey[k][0])
	}
	if len(s.sessions) >= s.limits.Max {
		s.sweepLocked()
		if len(s.sessions) >= s.limits.Max {
			return nil, "", ErrFull
		}
	}
	sess := &Session{
		id:        id,
		creds:     creds,
		principal: principal,
		csrf:      csrf,
		expires:   s.now().Add(s.ttl),
	}
	s.sessions[id] = sess
	s.byKey[k] = append(s.byKey[k], sess)
	return sess, id + "." + s.mac(id), nil
}

// Lookup returns the session the cookie value names, or nil when the value
// is malformed, its MAC is wrong, or the session is gone or expired. An
// expired session is dropped.
func (s *Store) Lookup(value string) *Session {
	id, mac, ok := strings.Cut(value, ".")
	if !ok || id == "" || !hmac.Equal([]byte(mac), []byte(s.mac(id))) {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.sessions[id]
	if sess == nil {
		return nil
	}
	if !s.now().Before(sess.expires) {
		s.removeLocked(sess)
		return nil
	}
	return sess
}

// FromRequest returns the session of r's cookie, or nil.
func (s *Store) FromRequest(r *http.Request) *Session {
	c, err := r.Cookie(CookieName)
	if err != nil {
		return nil
	}
	return s.Lookup(c.Value)
}

// Delete ends sess.
func (s *Store) Delete(sess *Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sessions[sess.id] == sess {
		s.removeLocked(sess)
	}
}

// Cookie returns the session cookie for value, for the response to r:
// HttpOnly, SameSite=Strict, for the whole site, lasting as long as the
// session, and Secure on a TLS connection or when the store is set so.
func (s *Store) Cookie(r *http.Request, value string) *http.Cookie {
	//nolint:gosec // G124: Secure is set by the connection and the setting, as documented
	return &http.Cookie{
		Name:     CookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   int(s.ttl.Seconds()),
		HttpOnly: true,
		Secure:   s.Secure(r),
		SameSite: http.SameSiteStrictMode,
	}
}

// ExpiredCookie returns the cookie that removes the session cookie.
func (s *Store) ExpiredCookie(r *http.Request) *http.Cookie {
	c := s.Cookie(r, "") //nolint:gosec // G124: Cookie sets every attribute
	c.MaxAge = -1
	return c
}

// Secure reports whether cookies for r are marked Secure.
func (s *Store) Secure(r *http.Request) bool {
	return s.secure || r.TLS != nil
}

func (s *Store) mac(id string) string {
	h := hmac.New(sha256.New, s.key)
	h.Write([]byte(id))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// randomToken returns 32 random bytes, base64url without padding.
func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("session: random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// RandomToken returns a fresh random token, for the sign-in form's CSRF
// cookie.
func RandomToken() (string, error) {
	return randomToken()
}
