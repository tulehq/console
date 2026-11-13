package mail_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"golang.org/x/net/html/atom"

	"tule.dev/console/internal/app"
	"tule.dev/console/internal/awsclient"
	"tule.dev/console/internal/consoletest"
	"tule.dev/console/internal/modules/mail"
)

// fakeMailbox serves /_mailbox/ from memory, refusing a request that is
// not signed for ses with the test key.
type fakeMailbox struct {
	messages    map[string]mail.Message
	disposition string
	queries     []url.Values
	deleted     []string
	resets      int
	reads       int
	mu          sync.Mutex
}

func (f *fakeMailbox) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential="+consoletest.KeyID+"/") ||
		!strings.Contains(auth, "/ses/aws4_request") {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"code":"UnrecognizedClientException","message":"unsigned"}`))
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/_mailbox/messages":
		f.list(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/_mailbox/rendering-failures":
		f.queries = append(f.queries, r.URL.Query())
		_ = json.NewEncoder(w).Encode(mail.FailurePage{Items: []mail.Failure{
			{
				MessageID: "m-failed",
				Template:  "Welcome",
				Source:    "SendEmail",
				From:      "a@example.com",
				To: []string{
					"b@example.com",
				},
				Error: "Attribute 'name' is not present in the rendering data.",
			},
		}})
	case r.Method == http.MethodDelete && r.URL.Path == "/_mailbox/messages":
		f.resets++
		clear(f.messages)
		w.WriteHeader(http.StatusNoContent)
	default:
		f.message(w, r, strings.Split(strings.TrimPrefix(r.URL.Path, "/_mailbox/messages/"), "/"))
	}
}

func (f *fakeMailbox) list(w http.ResponseWriter, r *http.Request) {
	f.queries = append(f.queries, r.URL.Query())
	items := make([]mail.Summary, 0, len(f.messages))
	for _, m := range f.messages {
		items = append(items, m.Summary)
	}
	page := mail.Page{Items: items}
	if r.URL.Query().Get("cursor") == "" && len(items) > 0 {
		page.NextCursor = "c2"
	}
	_ = json.NewEncoder(w).Encode(page)
}

// message serves /_mailbox/messages/{id} and what is under it.
func (f *fakeMailbox) message(w http.ResponseWriter, r *http.Request, parts []string) {
	m, ok := f.messages[parts[0]]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"code":"NotFoundException","message":"No message has that ID."}`))
		return
	}
	switch {
	case r.Method == http.MethodDelete:
		f.deleted = append(f.deleted, m.ID)
		delete(f.messages, m.ID)
		w.WriteHeader(http.StatusNoContent)
	case len(parts) == 1:
		f.reads++
		_ = json.NewEncoder(w).Encode(m)
	case parts[1] == "raw":
		w.Header().Set("Content-Type", "message/rfc822")
		_, _ = w.Write([]byte("Subject: " + m.Subject + "\r\n\r\n" + m.HTML))
	default:
		if f.disposition != "" {
			w.Header().Set("Content-Disposition", f.disposition)
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<script>alert('attached')</script>"))
	}
}

func message(id, subject, html string) mail.Message {
	return mail.Message{
		Summary: mail.Summary{
			ID: id, Time: "2026-11-13T10:00:00.123Z", From: "Sender <sender@example.com>",
			To: []string{"to@example.com"}, Subject: subject, Size: 924, AttachmentCount: 1,
			Tags: []mail.NameValue{{Name: "kind", Value: "welcome"}},
		},
		Text: "Hello in text.",
		HTML: html,
		Headers: []mail.NameValue{
			{Name: "Subject", Value: subject},
			{Name: "X-Custom", Value: "custom-value"},
		},
		Attachments: []mail.Attachment{{Name: "report.html", ContentType: "text/html", Size: 33}},
	}
}

func start(t *testing.T, f *fakeMailbox) *consoletest.Browser {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	ep := awsclient.Endpoint{URL: srv.URL, Region: "us-east-1", HTTP: srv.Client()}
	s := consoletest.Start(t, app.Overrides{Mailbox: func(c aws.Credentials) mail.API {
		return mail.NewClient(ep, c)
	}}, nil, "mail")
	b := s.Browser(t)
	b.SignIn(consoletest.KeyID, consoletest.Secret)
	return b
}

func TestListWithFilters(t *testing.T) {
	f := &fakeMailbox{
		messages: map[string]mail.Message{"m1": message("m1", "Welcome aboard", "<p>hi</p>")},
	}
	b := start(t, f)

	res := b.Get("/mail")
	consoletest.RequireStatus(t, res, http.StatusOK)
	consoletest.RequireText(
		t,
		res,
		"Welcome aboard",
		"Sender <sender@example.com>",
		"to@example.com",
		"kind:welcome",
	)
	if consoletest.Find(res.Doc, consoletest.LinkTo("/mail/message?id=m1")) == nil {
		t.Fatal("no link to the message")
	}

	q := url.Values{
		"q": {
			"welcome aboard",
		},
		"from":             {"sender@example.com"},
		"to":               {"to@example.com"},
		"subject":          {"Wel"},
		"since":            {"2026-11-13T09:00"},
		"until":            {"2026-11-13T11:30"},
		"configurationSet": {"cs"},
		"tag":              {"kind:welcome, team:growth"},
		"messageId":        {"0100abc"},
	}
	res = b.Get("/mail?" + q.Encode())
	consoletest.RequireStatus(t, res, http.StatusOK)
	got := f.queries[len(f.queries)-1]
	want := url.Values{
		"q": {
			"welcome aboard",
		},
		"from":    {"sender@example.com"},
		"to":      {"to@example.com"},
		"subject": {"Wel"},
		"since": {
			"2026-11-13T09:00:00Z",
		},
		"until":            {"2026-11-13T11:30:00Z"},
		"configurationSet": {"cs"},
		"tag":              {"kind:welcome", "team:growth"},
		"messageId":        {"0100abc"},
		"limit":            {"50"},
	}
	if got.Encode() != want.Encode() {
		t.Fatalf("the retrieval API got %v, want %v", got, want)
	}
}

func TestListPagesAndSearch(t *testing.T) {
	f := &fakeMailbox{
		messages: map[string]mail.Message{"m1": message("m1", "Welcome aboard", "<p>hi</p>")},
	}
	b := start(t, f)
	res := b.Get("/mail?from=sender%40example.com")

	// The next page keeps the filters.
	next := consoletest.Href(res.Doc, "Next page")
	u, err := url.Parse(next)
	if err != nil || u.Query().Get("cursor") != "c2" ||
		u.Query().Get("from") != "sender@example.com" {
		t.Fatalf("next page link %q", next)
	}
	b.Get(next)
	if f.queries[len(f.queries)-1].Get("cursor") != "c2" {
		t.Fatal("the cursor was not passed on")
	}

	// Search as you type: an HTMX request gets the results alone.
	res = b.HTMX("/mail?q=welcome")
	if strings.Contains(string(res.Body), "<form") ||
		!strings.Contains(string(res.Body), "Welcome aboard") {
		t.Fatalf("HTMX search answered %s", res.Body)
	}
}

// hostileHTML is a message's HTML part that would run, style and fetch.
const hostileHTML = `<p onclick="x()">Hello</p><script>alert(1)</script>` +
	`<img src="https://tracker.example/p.gif">`

func TestMessageView(t *testing.T) {
	f := &fakeMailbox{messages: map[string]mail.Message{"m1": message("m1", "Hi", hostileHTML)}}
	b := start(t, f)

	res := b.Get("/mail/message?id=m1")
	consoletest.RequireStatus(t, res, http.StatusOK)
	consoletest.RequireText(
		t,
		res,
		"Hello in text.",
		"X-Custom",
		"custom-value",
		"report.html",
		"text/html",
	)
	consoletest.RequireInert(t, res)

	frame := consoletest.Find(res.Doc, consoletest.Element(atom.Iframe))
	if frame == nil {
		t.Fatal("no preview frame")
	}
	if sb, ok := consoletest.Attr(frame, "sandbox"); !ok || sb != "" {
		t.Fatalf("frame sandbox=%q, want present and empty: no scripts, no same origin", sb)
	}
	if src, _ := consoletest.Attr(frame, "src"); src != "/mail/message/preview?id=m1" {
		t.Fatalf("frame src %q", src)
	}
}

// TestPreview checks the preview is the HTML as sent, under a policy that
// blocks everything, framable only by the console.
func TestPreview(t *testing.T) {
	f := &fakeMailbox{messages: map[string]mail.Message{"m1": message("m1", "Hi", hostileHTML)}}
	b := start(t, f)
	res := b.Get("/mail/message/preview?id=m1")
	consoletest.RequireStatus(t, res, http.StatusOK)
	if string(res.Body) != hostileHTML {
		t.Fatalf("preview %q", res.Body)
	}
	csp := res.Header.Get("Content-Security-Policy")
	for _, d := range []string{"default-src 'none'", "sandbox", "frame-ancestors 'self'", "form-action 'none'"} {
		if !strings.Contains(csp, d) {
			t.Fatalf("preview CSP %q lacks %s", csp, d)
		}
	}
	if strings.Contains(csp, "script-src") || strings.Contains(csp, "allow-") {
		t.Fatalf("preview CSP %q allows something", csp)
	}
	if res.Header.Get("X-Frame-Options") != "SAMEORIGIN" ||
		res.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("preview headers %v", res.Header)
	}
}

// TestRawAndAttachments checks raw MIME is plain text, sandboxed, and an
// attachment a sandboxed download.
func TestRawAndAttachments(t *testing.T) {
	f := &fakeMailbox{messages: map[string]mail.Message{"m1": message("m1", "Hi", hostileHTML)}}
	b := start(t, f)
	res := b.Get("/mail/message/raw?id=m1")
	if !strings.HasPrefix(res.Header.Get("Content-Type"), "text/plain") ||
		!strings.Contains(res.Header.Get("Content-Security-Policy"), "sandbox") ||
		res.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("raw headers %v", res.Header)
	}
	res = b.Get("/mail/message/raw?id=m1&save=1")
	if !strings.Contains(res.Header.Get("Content-Disposition"), `attachment; filename=m1.eml`) {
		t.Fatalf("save headers %v", res.Header)
	}
	res = b.Get("/mail/message/attachment?id=m1&index=0&name=report.html")
	consoletest.RequireStatus(t, res, http.StatusOK)
	if !strings.Contains(
		res.Header.Get("Content-Disposition"),
		"attachment; filename=report.html",
	) ||
		!strings.Contains(res.Header.Get("Content-Security-Policy"), "sandbox") {
		t.Fatalf("attachment headers %v", res.Header)
	}
	consoletest.RequireStatus(
		t,
		b.Get("/mail/message/attachment?id=m1&index=x"),
		http.StatusBadRequest,
	)
}

func TestMissingMessage(t *testing.T) {
	b := start(t, &fakeMailbox{messages: map[string]mail.Message{}})
	res := b.Get("/mail/message?id=nope")
	consoletest.RequireStatus(t, res, http.StatusNotFound)
	consoletest.RequireText(t, res, "NotFoundException", "No message has that ID.")
}

func TestDeleteAndReset(t *testing.T) {
	f := &fakeMailbox{
		messages: map[string]mail.Message{
			"m1": message("m1", "a", ""),
			"m2": message("m2", "b", ""),
		},
	}
	b := start(t, f)
	b.Get("/mail/message?id=m1")

	res := b.PostForm("/mail/message/delete", url.Values{"id": {"m1"}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Deleted the message.")
	if len(f.deleted) != 1 || f.deleted[0] != "m1" {
		t.Fatalf("deleted %v", f.deleted)
	}

	res = b.PostForm("/mail/reset", nil)
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Deleted every message")
	if f.resets != 1 || len(f.messages) != 0 {
		t.Fatal("the mailbox was not reset")
	}
}

func TestRenderingFailures(t *testing.T) {
	f := &fakeMailbox{messages: map[string]mail.Message{}}
	b := start(t, f)
	res := b.Get("/mail/failures?template=Welcome&since=2026-11-13T09%3A00")
	consoletest.RequireStatus(t, res, http.StatusOK)
	consoletest.RequireText(t, res, "Welcome", "Attribute 'name' is not present", "m-failed")
	got := f.queries[len(f.queries)-1]
	if got.Get("template") != "Welcome" || got.Get("since") != "2026-11-13T09:00:00Z" {
		t.Fatalf("the retrieval API got %v", got)
	}
}

func TestHostileMailRendersInert(t *testing.T) {
	f := &fakeMailbox{messages: map[string]mail.Message{}}
	for i, h := range consoletest.Hostile {
		m := message("h"+string(rune('a'+i)), h, h)
		m.From, m.To, m.Text = h, []string{h}, h
		m.Headers = []mail.NameValue{{Name: h, Value: h}}
		m.Attachments = []mail.Attachment{{Name: h, ContentType: h}}
		m.Tags = []mail.NameValue{{Name: h, Value: h}}
		f.messages[m.ID] = m
	}
	b := start(t, f)
	res := b.Get("/mail")
	consoletest.RequireInert(t, res)
	consoletest.RequireText(t, res, consoletest.Hostile...)
	for id := range f.messages {
		res = b.Get("/mail/message?id=" + id)
		consoletest.RequireStatus(t, res, http.StatusOK)
		consoletest.RequireInert(t, res)
	}
}

func TestAttachmentDoesNotReadTheMessage(t *testing.T) {
	f := &fakeMailbox{messages: map[string]mail.Message{"m1": message("m1", "Hi", "")}}
	b := start(t, f)
	page := b.Get("/mail/message?id=m1")
	link := consoletest.Href(page.Doc, "report.html")
	if link != "/mail/message/attachment?id=m1&index=0&name=report.html" {
		t.Fatalf("attachment link %q", link)
	}
	f.mu.Lock()
	f.reads = 0
	f.mu.Unlock()

	res := b.Get(link)
	consoletest.RequireStatus(t, res, http.StatusOK)
	if cd := res.Header.Get("Content-Disposition"); cd != "attachment; filename=report.html" {
		t.Fatalf("Content-Disposition %q", cd)
	}
	res = b.Get("/mail/message/attachment?id=m1&index=0")
	if cd := res.Header.Get("Content-Disposition"); cd != "attachment; filename=attachment-0" {
		t.Fatalf("Content-Disposition without a name %q", cd)
	}
	f.mu.Lock()
	reads := f.reads
	f.disposition = `attachment; filename="from-service.html"`
	f.mu.Unlock()
	if reads != 0 {
		t.Fatalf("the attachment route read the message %d times", reads)
	}

	// A name the service gives wins over the link's.
	res = b.Get(link)
	if cd := res.Header.Get("Content-Disposition"); cd != "attachment; filename=from-service.html" {
		t.Fatalf("Content-Disposition %q, want the service's name", cd)
	}
}
