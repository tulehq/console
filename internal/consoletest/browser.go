package consoletest

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/html"
)

// Browser is an HTTP client with a cookie jar that does not follow
// redirects, so a test sees each answer, and remembers the CSRF token of
// the last page it read.
type Browser struct {
	client *http.Client
	t      *testing.T
	base   string
	// CSRF is the _csrf value of the last page that had one.
	CSRF string
}

// Browser returns a fresh browser for s, signed out.
func (s *Server) Browser(t *testing.T) *Browser {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookie jar: %v", err)
	}
	return &Browser{
		t:    t,
		base: s.URL,
		client: &http.Client{
			Jar:     jar,
			Timeout: 30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Response is an answer, with its body parsed as HTML when it is HTML.
type Response struct {
	Header http.Header
	Doc    *html.Node
	Body   []byte
	Status int
}

// Location returns the redirect target.
func (r *Response) Location() string {
	return r.Header.Get("Location")
}

// Do sends req and reads the answer.
func (b *Browser) Do(req *http.Request) *Response {
	b.t.Helper()
	res, err := b.client.Do(req)
	if err != nil {
		b.t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		b.t.Fatalf("read %s %s: %v", req.Method, req.URL, err)
	}
	out := &Response{Status: res.StatusCode, Header: res.Header, Body: body}
	if strings.HasPrefix(res.Header.Get("Content-Type"), "text/html") {
		doc, perr := html.Parse(bytes.NewReader(body))
		if perr != nil {
			b.t.Fatalf("parse %s %s: %v", req.Method, req.URL, perr)
		}
		out.Doc = doc
		if v, ok := Attr(Find(doc, ByName("_csrf")), "value"); ok && v != "" {
			b.CSRF = v
		}
	}
	return out
}

// Request builds a request to path on the console.
func (b *Browser) Request(method, path string, body io.Reader) *http.Request {
	b.t.Helper()
	req, err := http.NewRequestWithContext(b.t.Context(), method, b.base+path, body)
	if err != nil {
		b.t.Fatalf("build %s %s: %v", method, path, err)
	}
	return req
}

// Get gets path.
func (b *Browser) Get(path string) *Response {
	b.t.Helper()
	return b.Do(b.Request(http.MethodGet, path, http.NoBody))
}

// HTMX gets path as HTMX does.
func (b *Browser) HTMX(path string) *Response {
	b.t.Helper()
	req := b.Request(http.MethodGet, path, http.NoBody)
	req.Header.Set("HX-Request", "true")
	return b.Do(req)
}

// PostForm posts form to path with the CSRF token of the last page, unless
// form has a _csrf of its own.
func (b *Browser) PostForm(path string, form url.Values) *Response {
	b.t.Helper()
	return b.Do(b.FormRequest(path, form))
}

// FormRequest builds the request PostForm sends.
func (b *Browser) FormRequest(path string, form url.Values) *http.Request {
	b.t.Helper()
	if form == nil {
		form = url.Values{}
	}
	if _, ok := form["_csrf"]; !ok {
		form.Set("_csrf", b.CSRF)
	}
	req := b.Request(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

// HTMXPost posts form as an HTMX request, with the token in its header.
func (b *Browser) HTMXPost(path string, form url.Values) *Response {
	b.t.Helper()
	req := b.Request(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	req.Header.Set("X-CSRF-Token", b.CSRF)
	return b.Do(req)
}

// Field is a field of a multipart form, a file when FileName is set.
type Field struct {
	Name        string
	Value       string
	FileName    string
	ContentType string
}

// PostMultipart posts fields, in order, as a multipart form, the CSRF field
// first as the console requires.
func (b *Browser) PostMultipart(path string, fields ...Field) *Response {
	b.t.Helper()
	return b.Do(b.MultipartRequest(path, fields...))
}

// MultipartRequest builds the request PostMultipart sends.
func (b *Browser) MultipartRequest(path string, fields ...Field) *http.Request {
	b.t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	all := append([]Field{{Name: "_csrf", Value: b.CSRF}}, fields...)
	for _, f := range all {
		var err error
		var part io.Writer
		if f.FileName != "" {
			h := make(map[string][]string)
			h["Content-Disposition"] = []string{
				`form-data; name="` + f.Name + `"; filename="` + f.FileName + `"`,
			}
			ct := f.ContentType
			if ct == "" {
				ct = "application/octet-stream"
			}
			h["Content-Type"] = []string{ct}
			part, err = w.CreatePart(h)
		} else {
			part, err = w.CreateFormField(f.Name)
		}
		if err == nil {
			_, err = io.WriteString(part, f.Value)
		}
		if err != nil {
			b.t.Fatalf("write multipart field %s: %v", f.Name, err)
		}
	}
	if err := w.Close(); err != nil {
		b.t.Fatalf("close multipart: %v", err)
	}
	req := b.Request(http.MethodPost, path, &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	return req
}

// Send sends req with the browser's cookies and returns the status, for
// use off the test's goroutine, where Do may not fail the test.
func (b *Browser) Send(req *http.Request) (int, error) {
	res, err := b.client.Do(req) //nolint:gosec // G704: a request to the console under test
	if err != nil {
		return 0, err //nolint:wrapcheck // the caller reports it
	}
	_, _ = io.Copy(io.Discard, res.Body)
	return res.StatusCode, res.Body.Close() //nolint:wrapcheck // the caller reports it
}

// SignIn signs in with the key, through the sign-in form, and fails the
// test unless the console accepted it.
func (b *Browser) SignIn(keyID, secret string) {
	b.t.Helper()
	res := b.TrySignIn(keyID, secret, "")
	if res.Status != http.StatusSeeOther {
		b.t.Fatalf("sign in: status %d, want 303: %s", res.Status, Text(res.Doc))
	}
	b.Get("/")
}

// TrySignIn fetches the sign-in form and posts the key with next, and
// returns the answer.
func (b *Browser) TrySignIn(keyID, secret, next string) *Response {
	b.t.Helper()
	page := b.Get("/signin")
	if page.Status != http.StatusOK {
		b.t.Fatalf("sign-in page: status %d", page.Status)
	}
	form := url.Values{"accessKeyId": {keyID}, "secretAccessKey": {secret}}
	if next != "" {
		form.Set("next", next)
	}
	return b.PostForm("/signin", form)
}

// Cookies returns the browser's cookies for the console.
func (b *Browser) Cookies() []*http.Cookie {
	u, err := url.Parse(b.base)
	if err != nil {
		b.t.Fatalf("parse base URL: %v", err)
	}
	return b.client.Jar.Cookies(u)
}
