// Package web holds what every page of the console shares: the embedded
// templates and static files, the renderer that wraps gas/ui with the
// layout's data, the middleware that signs requests in and checks their
// CSRF token, and the description of a service's failure for a page.
package web

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/gasmod/gas"
	"github.com/gasmod/gas/ui"

	"tule.dev/console/internal/awsclient"
	"tule.dev/console/internal/session"
)

// Section is one service the console shows: its key, the title in the
// navigation, the path its pages live under, and its endpoint.
type Section struct {
	Endpoint awsclient.Endpoint
	Key      string
	Title    string
	Path     string
}

// NavItem is a section in the navigation, with its reachability.
type NavItem struct {
	Key    string
	Title  string
	Path   string
	State  string
	Detail string
	Active bool
}

// View is the data every page is executed with. Data is the page's own.
type View struct {
	Data      any
	Flash     *session.Flash
	Status    *NavItem
	Principal session.Principal
	Title     string
	Section   string
	CSRF      string
	Nav       []NavItem
	SignedIn  bool
}

// Page is a page to render: its template name, title, section, data, the
// status to answer with (0 for 200), and the block an HTMX request for it
// renders instead of the whole page, empty to always render the whole page.
type Page struct {
	Data    any
	Name    string
	Title   string
	Section string
	Block   string
	Status  int
}

// Renderer renders pages through gas/ui with the layout's data.
type Renderer struct {
	ui       ui.Provider
	prober   *Prober
	sections []Section
}

// NewRenderer returns a renderer over provider for the configured sections,
// in navigation order.
func NewRenderer(provider ui.Provider, sections []Section) *Renderer {
	return &Renderer{ui: provider, sections: sections, prober: NewProber(sections)}
}

// Sections returns the configured sections, in navigation order.
func (r *Renderer) Sections() []Section {
	return r.sections
}

// Section returns the section of key, and whether it is configured.
func (r *Renderer) Section(key string) (Section, bool) {
	for _, s := range r.sections {
		if s.Key == key {
			return s, true
		}
	}
	return Section{}, false
}

// IsHTMX reports whether r is an HTMX request that may be answered with a
// fragment: not a history restore, which needs the whole page.
func IsHTMX(r *http.Request) bool {
	return r.Header.Get("HX-Request") == "true" &&
		r.Header.Get("HX-History-Restore-Request") != "true"
}

// Render renders p for the request of c: its block alone for an HTMX
// request when p names one, else the whole page in the layout.
func (r *Renderer) Render(c gas.Context, p Page) error {
	req := c.Request()
	sess := FromContext(req.Context())
	view := View{Title: p.Title, Section: p.Section, Data: p.Data}
	if sess != nil {
		view.SignedIn = true
		view.Principal = sess.Principal()
		view.CSRF = sess.CSRFToken()
	}

	var opts []ui.RenderOption
	if p.Status != 0 && p.Status != http.StatusOK {
		opts = append(opts, ui.WithStatus(p.Status))
	}
	c.ResponseWriter().Header().Add("Vary", "HX-Request")

	if p.Block != "" && IsHTMX(req) {
		opts = append(opts, ui.WithBlock(p.Block))
		//nolint:wrapcheck // gas/ui's errors name the operation and the page already
		return r.ui.RenderFragment(req.Context(), c.ResponseWriter(), p.Name, view, opts...)
	}

	if sess != nil {
		view.Flash = sess.PopFlash()
		view.Nav = r.nav(req.Context(), p.Section)
		for i := range view.Nav {
			if view.Nav[i].Active {
				view.Status = &view.Nav[i]
			}
		}
	}
	//nolint:wrapcheck // gas/ui's errors name the operation and the page already
	return r.ui.Render(req.Context(), c.ResponseWriter(), p.Name, view, opts...)
}

// nav returns the navigation, each section with its reachability.
func (r *Renderer) nav(ctx context.Context, active string) []NavItem {
	states := r.prober.States(ctx)
	items := make([]NavItem, len(r.sections))
	for i, s := range r.sections {
		items[i] = NavItem{
			Key:    s.Key,
			Title:  s.Title,
			Path:   s.Path,
			State:  states[i].State,
			Detail: states[i].Detail,
			Active: s.Key == active,
		}
	}
	return items
}

// proberTTL is how long a probe's answer is reused, so moving between pages
// does not probe every service each time.
const proberTTL = 5 * time.Second

// Prober probes the readiness of each section's service, at most once
// every proberTTL.
type Prober struct {
	at       time.Time
	states   []awsclient.Readiness
	sections []Section
	mu       sync.Mutex
}

// NewProber returns a prober of sections.
func NewProber(sections []Section) *Prober {
	return &Prober{sections: sections}
}

// States returns the readiness of each section, in order, probing them all
// at once when the last answers are older than proberTTL.
func (p *Prober) States(ctx context.Context) []awsclient.Readiness {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.states != nil && time.Since(p.at) < proberTTL {
		return p.states
	}
	// The answers are kept for others, so a probe is not cut short by the
	// request that happened to run it; each has its own timeout.
	ctx = context.WithoutCancel(ctx)
	states := make([]awsclient.Readiness, len(p.sections))
	var wg sync.WaitGroup
	for i, s := range p.sections {
		wg.Go(func() { states[i] = awsclient.Ready(ctx, s.Endpoint) })
	}
	wg.Wait()
	p.states, p.at = states, time.Now()
	return states
}
