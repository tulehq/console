package web

import (
	"context"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/gasmod/gas"

	"tule.dev/console/internal/session"
)

// CSRFField is the form field, and CSRFHeader the header, that carry a
// session's CSRF token.
const (
	CSRFField  = "_csrf"
	CSRFHeader = "X-CSRF-Token"
)

// SignInPath is the sign-in page every signed-out request is sent to.
const SignInPath = "/signin"

type sessionKey struct{}

type multipartKey struct{}

// FromContext returns the signed-in session of ctx, or nil.
func FromContext(ctx context.Context) *session.Session {
	s, _ := ctx.Value(sessionKey{}).(*session.Session)
	return s
}

// WithSession returns ctx carrying sess.
func WithSession(ctx context.Context, sess *session.Session) context.Context {
	return context.WithValue(ctx, sessionKey{}, sess)
}

// Public reports whether a path is served without a session: the sign-in
// page, the static files, the probes, and the files browsers and crawlers
// ask a site for on their own, which a page of the console never is.
func Public(path string) bool {
	switch path {
	case SignInPath, "/_health", "/_ready", "/favicon.ico", "/robots.txt":
		return true
	}
	return strings.HasPrefix(path, "/static/")
}

// pageNavigation reports whether r is the browser opening a page: a GET or
// HEAD that is a top-level navigation, by its Sec-Fetch headers when it
// has them, and never an HTMX request or a path with a file extension,
// which no page of the console has. Only a navigation is sent to sign-in;
// a background request, such as a browser's icon fetch, that followed a
// redirect there would load the sign-in page behind an open form.
func pageNavigation(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	if r.Header.Get("HX-Request") == "true" {
		return false
	}
	if mode := r.Header.Get("Sec-Fetch-Mode"); mode != "" && mode != "navigate" {
		return false
	}
	if dest := r.Header.Get("Sec-Fetch-Dest"); dest != "" && dest != "document" {
		return false
	}
	return !strings.Contains(path.Base(r.URL.Path), ".")
}

// Guard is the middleware that signs every request but the public ones in:
// a request without a live session is sent to sign-in, and a
// state-changing request must carry the session's CSRF token, in the
// X-CSRF-Token header or the _csrf form field (the first field of a
// multipart form). Signed-in responses are never cached.
func Guard(store *session.Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if Public(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			sess := store.FromRequest(r)
			if sess == nil {
				signedOut(w, r)
				return
			}

			ctx := WithSession(r.Context(), sess)
			if !safeMethod(r.Method) {
				var ok bool
				ctx, ok = checkCSRF(ctx, r, sess)
				if !ok {
					w.Header().Set("Cache-Control", "no-store")
					http.Error(w, "The form is missing its CSRF token or it is not this "+
						"session's. Reload the page and try again.", http.StatusForbidden)
					return
				}
			}

			w.Header().Set("Cache-Control", "no-store")
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func safeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead
}

// signedOut answers a request without a session. A page navigation is
// sent to sign-in by a 303 that comes back to it after; an HTMX request is
// told to go there by HX-Redirect, since a redirect would only swap the
// sign-in page into a fragment. Anything else, a form post, an asset or a
// background fetch, is a 401 that sends nowhere.
func signedOut(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", SignInPath)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if !pageNavigation(r) {
		WriteErrorPage(w, http.StatusUnauthorized, "Sign in to continue.")
		return
	}
	target := SignInPath
	if r.URL.Path != "/" {
		target += "?" + url.Values{"next": {r.URL.RequestURI()}}.Encode()
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// checkCSRF reports whether r carries sess's CSRF token. A multipart body
// is read up to its first part, which must be the token, and the reader
// positioned after it is put on the returned context for the handler.
func checkCSRF(
	ctx context.Context,
	r *http.Request,
	sess *session.Session,
) (context.Context, bool) {
	header := r.Header.Get(CSRFHeader)
	if isMultipart(r) {
		mr, err := r.MultipartReader()
		if err != nil {
			return ctx, false
		}
		ctx = context.WithValue(ctx, multipartKey{}, mr)
		if header != "" {
			return ctx, sess.CheckCSRF(header)
		}
		return ctx, sess.CheckCSRF(firstPartToken(mr))
	}
	// The form is parsed whichever carries the token, so a handler reads
	// PostForm the same for a form post and an HTMX one.
	if err := r.ParseForm(); err != nil {
		return ctx, false
	}
	if header != "" {
		return ctx, sess.CheckCSRF(header)
	}
	return ctx, sess.CheckCSRF(r.PostForm.Get(CSRFField))
}

func isMultipart(r *http.Request) bool {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && mt == "multipart/form-data"
}

// firstPartToken returns the value of the multipart body's first part when
// it is the _csrf field, and "" otherwise.
func firstPartToken(mr *multipart.Reader) string {
	part, err := mr.NextPart()
	if err != nil || part.FormName() != CSRFField {
		return ""
	}
	defer func() { _ = part.Close() }()
	b, err := io.ReadAll(io.LimitReader(part, 256))
	if err != nil {
		return ""
	}
	return string(b)
}

// ErrNoMultipart is returned by Multipart for a request whose body is not a
// multipart form.
var ErrNoMultipart = errors.New("the request is not a multipart form")

// Multipart returns the multipart reader of a state-changing request, past
// its CSRF field when the token came in the form.
func Multipart(r *http.Request) (*multipart.Reader, error) {
	if mr, ok := r.Context().Value(multipartKey{}).(*multipart.Reader); ok {
		return mr, nil
	}
	return nil, ErrNoMultipart
}

// Done records an ok flash for the session of c and sends the browser to
// target with a 303, after a successful action.
func Done(c gas.Context, target, message string) error {
	if sess := FromContext(c); sess != nil {
		sess.SetFlash("ok", message)
	}
	c.Redirect(http.StatusSeeOther, target)
	return nil
}

// Failed records an error flash describing err, prefixed by what, and
// sends the browser to target with a 303, after a failed action.
func Failed(c gas.Context, target, what string, err error) error {
	if sess := FromContext(c); sess != nil {
		sess.SetFlash("error", what+": "+Describe(err).Message)
	}
	c.Redirect(http.StatusSeeOther, target)
	return nil
}

// Invalid records an error flash with message and sends the browser to
// target, for a form the console refuses before calling a service.
func Invalid(c gas.Context, target, message string) error {
	if sess := FromContext(c); sess != nil {
		sess.SetFlash("error", message)
	}
	c.Redirect(http.StatusSeeOther, target)
	return nil
}
