package web

import (
	"fmt"
	"html/template"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gasmod/gas"
)

// Link returns path with the query of the key and value pairs, leaving out
// pairs whose value is empty. It is how pages build their links, so every
// value is query-escaped once, here.
func Link(path string, kv ...string) string {
	q := url.Values{}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] != "" {
			q.Add(kv[i], kv[i+1])
		}
	}
	if len(q) == 0 {
		return path
	}
	return path + "?" + q.Encode()
}

// Fail renders the section's error page for err, a failed service call,
// with the status Describe gives it.
func (r *Renderer) Fail(c gas.Context, section, title string, err error) error {
	f := Describe(err)
	return r.Render(c, Page{
		Name:    "error",
		Title:   title,
		Section: section,
		Status:  f.Status,
		Data:    f,
	})
}

// Funcs are the template functions the console adds to gas/ui's. None
// returns a trusted type, so html/template escapes everything they give.
func Funcs() template.FuncMap {
	return template.FuncMap{
		"bytes": FormatBytes,
		"when":  FormatTime,
		"link":  Link,
	}
}

// FormatBytes formats n bytes with a binary unit.
func FormatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// FormatTime formats t in UTC to the second, or "" for the zero time.
func FormatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02 15:04:05 UTC")
}

// FormatTimePtr is FormatTime of *t, "" for nil.
func FormatTimePtr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return FormatTime(*t)
}

// LocalPath reports whether p is a path of this site to send a browser to
// after sign-in: it starts with one slash and is no scheme-relative or
// backslash trick.
func LocalPath(p string) bool {
	return strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "//") &&
		!strings.ContainsAny(p, "\\\r\n\t") && !strings.HasPrefix(p, "/\\")
}

// sandboxCSP is the policy of every response that carries a service's
// bytes rather than a console page: nothing may load, run or be framed,
// and the document is sandboxed in an origin of its own should a browser
// show it rather than save it.
const sandboxCSP = "default-src 'none'; base-uri 'none'; form-action 'none'; " +
	"frame-ancestors 'none'; sandbox"

// AttachmentHeaders sets the headers of a download of a service's bytes:
// saved as name, never shown on the console's origin, typed contentType
// (application/octet-stream when it is not a media type) with sniffing off.
func AttachmentHeaders(h http.Header, name, contentType string) {
	if _, _, err := mime.ParseMediaType(contentType); err != nil || contentType == "" {
		contentType = "application/octet-stream"
	}
	h.Set("Content-Type", contentType)
	h.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{
		"filename": safeFileName(name),
	}))
	h.Set("Content-Security-Policy", sandboxCSP)
	h.Set("X-Content-Type-Options", "nosniff")
}

// InlineHeaders sets the headers of a service's bytes shown in the browser,
// such as a raw message as text: sandboxed as a download is, and with
// frame-ancestors relaxed to frame when frame is set.
func InlineHeaders(h http.Header, contentType string, frame bool) {
	h.Set("Content-Type", contentType)
	h.Set("X-Content-Type-Options", "nosniff")
	if frame {
		h.Set("Content-Security-Policy", strings.Replace(sandboxCSP,
			"frame-ancestors 'none'", "frame-ancestors 'self'", 1))
		h.Set("X-Frame-Options", "SAMEORIGIN")
		return
	}
	h.Set("Content-Security-Policy", sandboxCSP)
}

// safeFileName returns name without control characters, path separators or
// quotes, and "download" for a name with nothing left.
func safeFileName(name string) string {
	name = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == '/' || r == '\\' || r == '"' {
			return '_'
		}
		return r
	}, name)
	if strings.Trim(name, "._ ") == "" {
		return "download"
	}
	return name
}
