package web

import (
	"embed"
	"errors"
	"html/template"
	"io/fs"
	"net/http"

	"github.com/gasmod/gas"
)

//go:embed templates
var templatesFS embed.FS

//go:embed static
var staticFS embed.FS

// Templates returns the page templates, rooted at their store names.
func Templates() fs.FS {
	sub, err := fs.Sub(templatesFS, "templates")
	if err != nil {
		panic(err) // the embedded directory is there by construction
	}
	return sub
}

// Static returns the static files served under /static/.
func Static() fs.FS {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err) // the embedded directory is there by construction
	}
	return sub
}

// errorPage is the page of an error no handler rendered itself: a route
// that does not exist, or a fault of the console. It stands apart from the
// template store, so it renders even when the store cannot.
var errorPage = template.Must(template.New("error").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}} | Tule console</title>
<link rel="icon" href="data:,">
<link rel="stylesheet" href="/static/console.css"></head>
<body class="bare"><main class="bare-main">
<h1>{{.Title}}</h1><p>{{.Message}}</p><p><a href="/">Go to the console</a></p>
</main></body></html>`))

// WriteErrorPage writes the plain error page for status with message.
func WriteErrorPage(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = errorPage.Execute(w, struct{ Title, Message string }{http.StatusText(status), message})
}

// ErrorHandler is the app's gas.ErrorHandler: it logs the error as gas's
// default does, and answers with the plain error page. The message of a
// *gas.Error is shown, as gas shows it; any other error is a fault of the
// console and shows nothing of itself.
func ErrorHandler(c gas.Context, err error) {
	status, message := http.StatusInternalServerError, "The console failed to answer this request."
	var ge *gas.Error
	if errors.As(err, &ge) && ge.Status >= 400 && ge.Status <= 599 {
		status, message = ge.Status, ge.Message
	}
	logger := gas.LoggerFromContext(c)
	if logger != nil {
		if status >= http.StatusInternalServerError {
			logger.Error("request error").Err("error", err).Send()
		} else {
			logger.Warn("request error").Err("error", err).Send()
		}
	}
	WriteErrorPage(c.ResponseWriter(), status, message)
}

// NotFound answers a path no route serves.
func NotFound(w http.ResponseWriter, _ *http.Request) {
	WriteErrorPage(w, http.StatusNotFound, "There is no page at this address.")
}
