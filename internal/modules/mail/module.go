// Package mail is the mailbox section: the stored messages with every
// filter of mailbox's retrieval API and full-text search, a message with
// its headers, text, an HTML preview in a sandboxed frame, its raw MIME and
// attachments, the rendering failures, deleting one message or all, and
// the email identities with their sending authorization policies.
package mail

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/gasmod/gas"

	"tule.dev/console/internal/web"
)

// Key is the section's key, and Path the path its pages live under.
const (
	Key  = "mail"
	Path = "/mail"
)

const (
	moduleName = "tule/modules/mail"
	// pageSize is how many messages a page shows.
	pageSize = "50"
)

// Clients are the two APIs the section calls: mailbox's retrieval API and
// the SES v2 API.
type Clients struct {
	Retrieval API
	SES       SES
}

// NewClients returns the clients for a session's credentials.
type NewClients func(aws.Credentials) Clients

// Module serves the section.
type Module struct {
	router     *gas.Router
	render     *web.Renderer
	newClients NewClients
}

// NewModule returns the module. It registers its routes when the app
// initializes it.
func NewModule(router *gas.Router, render *web.Renderer, newClients NewClients) *Module {
	return &Module{router: router, render: render, newClients: newClients}
}

// Name identifies the module to gas.
func (m *Module) Name() string { return moduleName }

// Init registers the module's routes.
func (m *Module) Init(context.Context) error {
	m.router.Route(m, Path, func(g *gas.RouteGroup) {
		g.Get("/", m.messages)
		g.Get("/message", m.message)
		g.Get("/message/preview", m.preview)
		g.Get("/message/raw", m.raw)
		g.Get("/message/attachment", m.attachment)
		g.Post("/message/delete", m.remove)
		g.Post("/reset", m.reset)
		g.Get("/failures", m.failures)
		g.Get("/identities", m.identities)
		g.Get("/identity", m.identity)
		g.Post("/identity/policy", m.putPolicy)
		g.Post("/identity/policy/delete", m.deletePolicy)
	})
	return nil
}

// Close releases nothing; the module holds no resources of its own.
func (m *Module) Close(context.Context) error { return nil }

func (m *Module) api(c gas.Context) API {
	return m.newClients(web.FromContext(c).Credentials()).Retrieval
}

func (m *Module) ses(c gas.Context) SES {
	return m.newClients(web.FromContext(c).Credentials()).SES
}

func messageLink(id string) string {
	return web.Link(Path+"/message", "id", id)
}

// messageFilters are the retrieval API's filters of the message list, in
// the order the form shows them.
var messageFilters = []string{
	"q", "from", "to", "subject", "since", "until", "configurationSet", "tag", "messageId",
}

// Filters is the filter form's values.
type Filters struct {
	Q                string
	From             string
	To               string
	Subject          string
	Since            string
	Until            string
	ConfigurationSet string
	Tag              string
	MessageID        string
	Active           bool
}

// Row is a message in the list.
type Row struct {
	At   time.Time
	Link string
	Summary
}

type listView struct {
	NextLink  string
	FirstLink string
	Rows      []Row
	Filters   Filters
}

// apiQuery maps the console's query to the retrieval API's: the filters
// as given, times from the form's local date and time to RFC 3339 in UTC,
// and tags split at commas, each its own tag parameter.
func apiQuery(in url.Values, names []string) url.Values {
	out := url.Values{}
	for _, name := range names {
		v := strings.TrimSpace(in.Get(name))
		if v == "" {
			continue
		}
		switch name {
		case "since", "until":
			out.Set(name, toRFC3339(v))
		case "tag":
			for t := range strings.SplitSeq(v, ",") {
				if t = strings.TrimSpace(t); t != "" {
					out.Add("tag", t)
				}
			}
		default:
			out.Set(name, v)
		}
	}
	return out
}

// toRFC3339 turns the value of a datetime-local input, read as UTC, into
// RFC 3339, and leaves any other value to the service to judge.
func toRFC3339(v string) string {
	for _, layout := range []string{"2006-01-02T15:04", "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, v); err == nil {
			return t.UTC().Format(time.RFC3339)
		}
	}
	return v
}

func filtersOf(q url.Values) Filters {
	f := Filters{
		Q: q.Get("q"), From: q.Get("from"), To: q.Get("to"), Subject: q.Get("subject"),
		Since: q.Get("since"), Until: q.Get("until"), ConfigurationSet: q.Get("configurationSet"),
		Tag: q.Get("tag"), MessageID: q.Get("messageId"),
	}
	f.Active = f.From != "" || f.To != "" || f.Subject != "" || f.Since != "" || f.Until != "" ||
		f.ConfigurationSet != "" || f.Tag != "" || f.MessageID != ""
	return f
}

// pageLinks returns the link to the next page, after cursor next, and to
// the first, of the list at path filtered by q.
func pageLinks(path string, q url.Values, names []string, next string) (nextLink, first string) {
	kv := make([]string, 0, 2*len(names)+2)
	for _, n := range names {
		kv = append(kv, n, q.Get(n))
	}
	if next != "" {
		nextLink = web.Link(path, append(kv, "cursor", next)...)
	}
	if q.Get("cursor") != "" {
		first = web.Link(path, kv...)
	}
	return nextLink, first
}

func (m *Module) messages(c gas.Context) error {
	q := c.Request().URL.Query()
	query := apiQuery(q, messageFilters)
	query.Set("limit", pageSize)
	if cur := q.Get("cursor"); cur != "" {
		query.Set("cursor", cur)
	}
	p, err := m.api(c).Messages(c, query)
	if err != nil {
		return m.render.Fail(c, Key, "Messages", err)
	}
	v := listView{Filters: filtersOf(q)}
	for _, s := range p.Items {
		at, _ := time.Parse(time.RFC3339Nano, s.Time)
		v.Rows = append(v.Rows, Row{Summary: s, At: at, Link: messageLink(s.ID)})
	}
	v.NextLink, v.FirstLink = pageLinks(Path, q, messageFilters, p.NextCursor)
	return m.render.Render(c, web.Page{
		Name: "mail/messages", Title: "Messages", Section: Key, Data: v, Block: "results",
	})
}

// AttachmentRow is an attachment with its download link.
type AttachmentRow struct {
	Link string
	Attachment
}

type messageView struct {
	At          time.Time
	Preview     string
	RawLink     string
	SaveLink    string
	Attachments []AttachmentRow
	Message
}

func (m *Module) message(c gas.Context) error {
	id := c.Query("id")
	msg, err := m.api(c).Message(c, id)
	if err != nil {
		return m.render.Fail(c, Key, "Message", err)
	}
	at, _ := time.Parse(time.RFC3339Nano, msg.Time)
	v := messageView{
		Message:  msg,
		At:       at,
		RawLink:  web.Link(Path+"/message/raw", "id", id),
		SaveLink: web.Link(Path+"/message/raw", "id", id, "save", "1"),
	}
	if msg.HTML != "" {
		v.Preview = web.Link(Path+"/message/preview", "id", id)
	}
	for i, a := range msg.Attachments {
		v.Attachments = append(v.Attachments, AttachmentRow{
			Attachment: a,
			Link: web.Link(Path+"/message/attachment",
				"id", id, "index", strconv.Itoa(i), "name", a.Name),
		})
	}
	title := msg.Subject
	if title == "" {
		title = "(no subject)"
	}
	return m.render.Render(c, web.Page{Name: "mail/message", Title: title, Section: Key, Data: v})
}

// preview answers the message's HTML part as a document for the sandboxed
// frame of the message page. Its policy blocks everything, scripts,
// styles, images and every other fetch included, and sandboxes it in an
// origin of its own even when it is opened outside the frame.
func (m *Module) preview(c gas.Context) error {
	msg, err := m.api(c).Message(c, c.Query("id"))
	if err != nil {
		return m.render.Fail(c, Key, "Message", err)
	}
	h := c.ResponseWriter().Header()
	web.InlineHeaders(h, "text/html; charset=utf-8", true)
	h.Set("Referrer-Policy", "no-referrer")
	c.ResponseWriter().WriteHeader(http.StatusOK)
	_, _ = io.WriteString(c.ResponseWriter(), msg.HTML)
	return nil
}

// raw streams the message's MIME: as plain text to read in the browser, or
// as a .eml file to save with save=1.
func (m *Module) raw(c gas.Context) error {
	id := c.Query("id")
	b, err := m.api(c).Raw(c, id)
	if err != nil {
		return m.render.Fail(c, Key, "Message", err)
	}
	defer func() { _ = b.Reader.Close() }()
	h := c.ResponseWriter().Header()
	if c.Query("save") == "1" {
		web.AttachmentHeaders(h, id+".eml", "message/rfc822")
	} else {
		web.InlineHeaders(h, "text/plain; charset=utf-8", false)
	}
	return stream(c, b)
}

// attachment streams one attachment as a download. Its file name is the
// one the service gives, else the name the message page put in the link
// (it names only the saved file, and is made safe as every file name is),
// else attachment-<index>, so the message itself is never fetched for it.
func (m *Module) attachment(c gas.Context) error {
	id := c.Query("id")
	index, err := strconv.Atoi(c.Query("index"))
	if err != nil || index < 0 {
		return m.render.Fail(c, Key, "Attachment",
			&web.BadInput{Message: "The attachment index is not a number."})
	}
	b, err := m.api(c).Attachment(c, id, index)
	if err != nil {
		return m.render.Fail(c, Key, "Attachment", err)
	}
	defer func() { _ = b.Reader.Close() }()
	name := b.FileName
	if name == "" {
		name = c.Query("name")
	}
	if name == "" {
		name = "attachment-" + strconv.Itoa(index)
	}
	web.AttachmentHeaders(c.ResponseWriter().Header(), name, b.ContentType)
	return stream(c, b)
}

// stream copies b to the response.
func stream(c gas.Context, b Body) error {
	if b.Length >= 0 {
		c.ResponseWriter().Header().Set("Content-Length", strconv.FormatInt(b.Length, 10))
	}
	c.ResponseWriter().WriteHeader(http.StatusOK)
	if _, err := io.Copy(c.ResponseWriter(), b.Reader); err != nil {
		// The status is sent; the response can only be cut short.
		panic(http.ErrAbortHandler)
	}
	return nil
}

func (m *Module) remove(c gas.Context) error {
	id := c.Request().PostForm.Get("id")
	if err := m.api(c).Delete(c, id); err != nil {
		return web.Failed(c, messageLink(id), "The message was not deleted", err)
	}
	return web.Done(c, Path, "Deleted the message.")
}

func (m *Module) reset(c gas.Context) error {
	if err := m.api(c).Reset(c); err != nil {
		return web.Failed(c, Path, "The mailbox was not emptied", err)
	}
	return web.Done(c, Path, "Deleted every message and rendering failure.")
}

var failureFilters = []string{"messageId", "template", "since", "until"}

type failuresView struct {
	MessageID string
	Template  string
	Since     string
	Until     string
	NextLink  string
	FirstLink string
	Items     []Failure
}

func (m *Module) failures(c gas.Context) error {
	q := c.Request().URL.Query()
	query := apiQuery(q, failureFilters)
	query.Set("limit", pageSize)
	if cur := q.Get("cursor"); cur != "" {
		query.Set("cursor", cur)
	}
	p, err := m.api(c).Failures(c, query)
	if err != nil {
		return m.render.Fail(c, Key, "Rendering failures", err)
	}
	v := failuresView{
		MessageID: q.Get("messageId"), Template: q.Get("template"),
		Since: q.Get("since"), Until: q.Get("until"), Items: p.Items,
	}
	v.NextLink, v.FirstLink = pageLinks(Path+"/failures", q, failureFilters, p.NextCursor)
	return m.render.Render(c, web.Page{
		Name: "mail/failures", Title: "Rendering failures", Section: Key, Data: v,
	})
}
