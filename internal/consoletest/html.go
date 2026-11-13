package consoletest

import (
	"fmt"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// Match reports whether a node is the one looked for.
type Match func(*html.Node) bool

// Attr returns n's attribute key.
func Attr(n *html.Node, key string) (string, bool) {
	if n == nil {
		return "", false
	}
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val, true
		}
	}
	return "", false
}

// Find returns the first node under n that m matches, in document order,
// or nil.
func Find(n *html.Node, m Match) *html.Node {
	if n == nil {
		return nil
	}
	if m(n) {
		return n
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if f := Find(c, m); f != nil {
			return f
		}
	}
	return nil
}

// FindAll returns every node under n that m matches, in document order.
func FindAll(n *html.Node, m Match) []*html.Node {
	var out []*html.Node
	var walk func(*html.Node)
	walk = func(x *html.Node) {
		if m(x) {
			out = append(out, x)
		}
		for c := x.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	if n != nil {
		walk(n)
	}
	return out
}

// Element matches an element of tag a.
func Element(a atom.Atom) Match {
	return func(n *html.Node) bool { return n.Type == html.ElementNode && n.DataAtom == a }
}

// ByID matches the element with id.
func ByID(id string) Match {
	return func(n *html.Node) bool {
		v, ok := Attr(n, "id")
		return n.Type == html.ElementNode && ok && v == id
	}
}

// ByName matches the element with the name attribute name.
func ByName(name string) Match {
	return func(n *html.Node) bool {
		v, ok := Attr(n, "name")
		return n.Type == html.ElementNode && ok && v == name
	}
}

// LinkTo matches an a element whose href is href.
func LinkTo(href string) Match {
	return func(n *html.Node) bool {
		v, ok := Attr(n, "href")
		return n.Type == html.ElementNode && n.DataAtom == atom.A && ok && v == href
	}
}

// FormTo matches a form whose action is action.
func FormTo(action string) Match {
	return func(n *html.Node) bool {
		v, ok := Attr(n, "action")
		return n.Type == html.ElementNode && n.DataAtom == atom.Form && ok && v == action
	}
}

// WithText matches an element whose text, spaces collapsed, holds s.
func WithText(a atom.Atom, s string) Match {
	return func(n *html.Node) bool {
		return n.Type == html.ElementNode && n.DataAtom == a && strings.Contains(Text(n), s)
	}
}

// Text returns the text under n, runs of space collapsed to one.
func Text(n *html.Node) string {
	if n == nil {
		return ""
	}
	var b strings.Builder
	var walk func(*html.Node)
	walk = func(x *html.Node) {
		if x.Type == html.TextNode {
			b.WriteString(x.Data)
		}
		for c := x.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return strings.Join(strings.Fields(b.String()), " ")
}

// RequireText fails unless the page's text holds each of want.
func RequireText(t *testing.T, r *Response, want ...string) {
	t.Helper()
	text := Text(r.Doc)
	for _, w := range want {
		if !strings.Contains(text, w) {
			t.Fatalf("page text does not hold %q:\n%s", w, text)
		}
	}
}

// RequireStatus fails unless r has status.
func RequireStatus(t *testing.T, r *Response, status int) {
	t.Helper()
	if r.Status != status {
		t.Fatalf("status %d, want %d: %s", r.Status, status, Text(r.Doc))
	}
}

// RequireFlash fails unless the page shows an ok banner holding want.
func RequireFlash(t *testing.T, r *Response, kind, want string) {
	t.Helper()
	cls := "banner-" + kind
	n := Find(r.Doc, func(n *html.Node) bool {
		c, _ := Attr(n, "class")
		return n.Type == html.ElementNode && strings.Contains(c, cls)
	})
	if n == nil || !strings.Contains(Text(n), want) {
		t.Fatalf("no %s banner holding %q: %s", kind, want, Text(r.Doc))
	}
}

// RequireInert fails unless the page runs nothing it was not built to: no
// script but the console's own files, no event handler attribute, and no
// javascript: URL. Tests render hostile service data and call it.
func RequireInert(t *testing.T, r *Response) {
	t.Helper()
	if r.Doc == nil {
		t.Fatal("the answer is not HTML")
	}
	for _, s := range FindAll(r.Doc, Element(atom.Script)) {
		src, _ := Attr(s, "src")
		if !strings.HasPrefix(src, "/static/") || s.FirstChild != nil {
			t.Fatalf("a script the console did not write: src=%q text=%q", src, Text(s))
		}
	}
	for _, n := range FindAll(r.Doc, func(n *html.Node) bool { return n.Type == html.ElementNode }) {
		if msg := activeAttr(n); msg != "" {
			t.Fatal(msg)
		}
		if msg := activeElement(n); msg != "" {
			t.Fatal(msg)
		}
	}
}

// activeAttr describes an attribute of n that would run code: an event
// handler or a javascript: URL, or "".
func activeAttr(n *html.Node) string {
	for _, a := range n.Attr {
		k := strings.ToLower(a.Key)
		v := strings.ToLower(strings.TrimSpace(a.Val))
		if strings.HasPrefix(k, "on") {
			return fmt.Sprintf("event handler attribute %s=%q on <%s>", a.Key, a.Val, n.Data)
		}
		urlAttr := k == "href" || k == "src" || k == "action" || k == "formaction"
		if urlAttr && strings.HasPrefix(v, "javascript:") {
			return fmt.Sprintf("javascript URL %s=%q on <%s>", a.Key, a.Val, n.Data)
		}
	}
	return ""
}

// activeElement describes n when it is an element the console never
// writes, or a frame that is not fully sandboxed, or "".
func activeElement(n *html.Node) string {
	switch n.DataAtom {
	case atom.Iframe:
		if sb, ok := Attr(n, "sandbox"); !ok || sb != "" {
			return fmt.Sprintf("an iframe that is not fully sandboxed: sandbox=%q", sb)
		}
	case atom.Img, atom.Object, atom.Embed, atom.Base:
		return fmt.Sprintf("an element the console never writes: <%s>", n.Data)
	}
	return ""
}

// Hostile are strings no service should send and every page must show as
// text: markup, an attribute break-out, a script URL and a template
// action.
var Hostile = []string{
	`<script>alert(1)</script>`,
	`"><img src=x onerror=alert(1)>`,
	`javascript:alert(1)`,
	`'><svg onload=alert(1)>`,
	`{{.CSRF}}`,
}

// HostileName is one string that holds every hostile part.
const HostileName = `x"><script>alert(1)</script><img src=x onerror=alert(1)>javascript:alert(1)`

// Href returns the href of the first link whose text is text, or "".
func Href(doc *html.Node, text string) string {
	for _, a := range FindAll(doc, Element(atom.A)) {
		if Text(a) == text {
			v, _ := Attr(a, "href")
			return v
		}
	}
	return ""
}

// FormHolding matches a form that holds the element of id.
func FormHolding(id string) Match {
	return func(n *html.Node) bool {
		return n.Type == html.ElementNode && n.DataAtom == atom.Form && Find(n, ByID(id)) != nil
	}
}

// Hidden returns the hidden fields of the page's first form form matches,
// the CSRF token left out, with kv set over them: what a browser sends
// when that form is submitted with those fields filled in.
func Hidden(r *Response, form Match, kv ...string) url.Values {
	v := url.Values{}
	if form := Find(r.Doc, form); form != nil {
		for _, in := range FindAll(form, Element(atom.Input)) {
			typ, _ := Attr(in, "type")
			name, _ := Attr(in, "name")
			if typ == "hidden" && name != "" && name != "_csrf" {
				value, _ := Attr(in, "value")
				v.Add(name, value)
			}
		}
	}
	for i := 0; i+1 < len(kv); i += 2 {
		v.Set(kv[i], kv[i+1])
	}
	return v
}
