// Package signin serves the sign-in and sign-out of the console and its
// overview page.
package signin

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/gasmod/gas"

	"tule.dev/console/internal/httpx"
	"tule.dev/console/internal/session"
	"tule.dev/console/internal/web"
)

const moduleName = "tule/modules/signin"

// formCookie carries the sign-in form's own CSRF token, before there is a
// session to hold one: the form must post back the token its cookie holds.
const formCookie = "tule_console_signin"

// The longest values the form takes: AWS's access key IDs are at most 128
// characters, and a session token is far below 8 KiB.
const (
	maxKeyID  = 128
	maxSecret = 256
	maxToken  = 8192
)

// Deps are what the module needs besides the router and the renderer.
type Deps struct {
	Store   *session.Store
	Verify  Verifier
	Limiter *web.Limiter
}

// Module serves /signin, /signout and the overview at /.
type Module struct {
	router *gas.Router
	render *web.Renderer
	deps   Deps
}

// NewModule returns the module. It registers its routes when the app
// initializes it.
func NewModule(router *gas.Router, render *web.Renderer, deps Deps) *Module {
	return &Module{router: router, render: render, deps: deps}
}

// Name identifies the module to gas.
func (m *Module) Name() string { return moduleName }

// Init registers the module's routes.
func (m *Module) Init(context.Context) error {
	m.router.Get(m, web.SignInPath, m.signInPage)
	m.router.Post(m, web.SignInPath, m.signIn)
	m.router.Post(m, "/signout", m.signOut)
	m.router.Get(m, "/", m.overview)
	m.router.Get(m, "/robots.txt", robots)
	return nil
}

// Close releases nothing; the module holds no resources of its own.
func (m *Module) Close(context.Context) error { return nil }

type signInView struct {
	Token string
	Next  string
	Error string
}

func (m *Module) signInPage(c gas.Context) error {
	if m.deps.Store.FromRequest(c.Request()) != nil {
		c.Redirect(http.StatusSeeOther, "/")
		return nil
	}
	return m.showForm(c, http.StatusOK, c.Query("next"), "")
}

// showForm renders the sign-in form with the browser's form token. A token
// the browser holds and that is still good is kept, so a second render of
// the form, such as one a background request follows to, never leaves an
// open form with a token that no longer matches; a new one is issued only
// when the browser has none, or one that is forged or expired.
func (m *Module) showForm(c gas.Context, status int, next, message string) error {
	token := ""
	if cookie, err := c.Request().
		Cookie(formCookie); err == nil &&
		m.deps.Store.ValidFormToken(cookie.Value) {
		token = cookie.Value
	}
	if token == "" {
		var err error
		if token, err = m.deps.Store.NewFormToken(); err != nil {
			return err
		}
		http.SetCookie(c.ResponseWriter(),
			m.formCookie(c.Request(), token, int(session.FormTokenTTL.Seconds())))
	}
	c.SetHeader("Cache-Control", "no-store")
	if !web.LocalPath(next) {
		next = ""
	}
	return m.render.Render(c, web.Page{
		Name:   "signin",
		Title:  "Sign in",
		Status: status,
		Data:   signInView{Token: token, Next: next, Error: message},
	})
}

func (m *Module) signIn(c gas.Context) error {
	r := c.Request()
	if err := r.ParseForm(); err != nil {
		return m.showForm(c, http.StatusBadRequest, "", "The form could not be read.")
	}
	next := r.PostForm.Get("next")

	if m.deps.Limiter.Blocked(r) {
		return m.showForm(c, http.StatusTooManyRequests, next,
			"Too many failed sign-ins from this address. Wait a minute and try again.")
	}
	if !m.formTokenOK(r) {
		m.deps.Limiter.Fail(r)
		return m.showForm(c, http.StatusForbidden, next,
			"The sign-in form expired. Enter the key again.")
	}

	creds, problem := formCredentials(r.PostForm)
	if problem != "" {
		m.deps.Limiter.Fail(r)
		return m.showForm(c, http.StatusBadRequest, next, problem)
	}

	principal, err := m.deps.Verify(r.Context(), creds)
	if err != nil {
		return m.notVerified(c, next, err)
	}

	_, value, err := m.deps.Store.Create(creds, principal)
	if errors.Is(err, session.ErrFull) {
		return m.showForm(
			c,
			http.StatusServiceUnavailable,
			next,
			"The console holds as many sessions as it allows. Sign in again once some have ended or expired.",
		)
	}
	if err != nil {
		return err
	}
	// Signing in again ends the session the browser had.
	if old := m.deps.Store.FromRequest(r); old != nil {
		m.deps.Store.Delete(old)
	}
	http.SetCookie(c.ResponseWriter(), m.deps.Store.Cookie(r, value))
	http.SetCookie(c.ResponseWriter(), m.formCookie(r, "", -1))
	if !web.LocalPath(next) {
		next = "/"
	}
	c.Redirect(http.StatusSeeOther, next)
	return nil
}

// notVerified answers a sign-in whose key was refused or could not be
// checked. A refusal counts against the client. The detail of a check that
// failed names endpoints and the SDK's text: it goes to the log, and the
// signed-out visitor sees only which service failed.
func (m *Module) notVerified(c gas.Context, next string, err error) error {
	if errors.Is(err, ErrRefused) {
		m.deps.Limiter.Fail(c.Request())
		return m.showForm(
			c,
			http.StatusUnauthorized,
			next,
			"The key was refused: the service does not know this access key, or the secret does not match.",
		)
	}
	httpx.Logger(c).Warn("sign-in could not verify the key").Err("error", err).Send()
	message := "The key could not be verified: the service is unreachable."
	var uv *UnverifiedError
	if errors.As(err, &uv) {
		message = uv.Message()
	}
	return m.showForm(c, http.StatusBadGateway, next, message)
}

// formCookie returns the sign-in form's token cookie for the response to r,
// lasting maxAge seconds (-1 removes it). It is HttpOnly, SameSite=Strict,
// for the sign-in path only, and Secure as the session cookie is.
func (m *Module) formCookie(r *http.Request, value string, maxAge int) *http.Cookie {
	//nolint:gosec // G124: Secure is set as the session cookie's, by the connection and the setting
	return &http.Cookie{
		Name:     formCookie,
		Value:    value,
		Path:     web.SignInPath,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   m.deps.Store.Secure(r),
		SameSite: http.SameSiteStrictMode,
	}
}

// formCredentials reads the key from the sign-in form, or says what is
// wrong with it.
func formCredentials(form url.Values) (aws.Credentials, string) {
	creds := aws.Credentials{
		AccessKeyID:     strings.TrimSpace(form.Get("accessKeyId")),
		SecretAccessKey: strings.TrimSpace(form.Get("secretAccessKey")),
		SessionToken:    strings.TrimSpace(form.Get("sessionToken")),
	}
	if creds.AccessKeyID == "" || creds.SecretAccessKey == "" {
		return creds, "Enter an access key ID and its secret access key."
	}
	if len(creds.AccessKeyID) > maxKeyID || len(creds.SecretAccessKey) > maxSecret ||
		len(creds.SessionToken) > maxToken {
		return creds, "The key is longer than any AWS key."
	}
	return creds, ""
}

// formTokenOK reports whether the form posted back the token its cookie
// holds, and that token is one the store issued and still good.
func (m *Module) formTokenOK(r *http.Request) bool {
	cookie, err := r.Cookie(formCookie)
	if err != nil || !m.deps.Store.ValidFormToken(cookie.Value) {
		return false
	}
	posted := r.PostForm.Get(web.CSRFField)
	return subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(posted)) == 1
}

func (m *Module) signOut(c gas.Context) error {
	if sess := web.FromContext(c); sess != nil {
		m.deps.Store.Delete(sess)
	}
	http.SetCookie(c.ResponseWriter(), m.deps.Store.ExpiredCookie(c.Request()))
	c.Redirect(http.StatusSeeOther, web.SignInPath)
	return nil
}

// robots asks crawlers to keep out: the console is a tool, not a site.
func robots(c gas.Context) error {
	return c.Text(http.StatusOK, "User-agent: *\nDisallow: /\n")
}

func (m *Module) overview(c gas.Context) error {
	return m.render.Render(c, web.Page{Name: "overview", Title: "Overview"})
}
