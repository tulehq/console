package awsclient

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// readyTimeout bounds one readiness probe, so a service that hangs shows
// as unreachable instead of holding the page.
const readyTimeout = 2 * time.Second

// Readiness is what a service's /_ready answered.
type Readiness struct {
	// State is "ready", "not ready" (it answered, not 200) or
	// "unreachable" (it did not answer).
	State string
	// Detail says why, for a service that is not ready.
	Detail string
}

// Ready reports whether a service is ready from its unsigned /_ready probe.
func Ready(ctx context.Context, e Endpoint) Readiness {
	ctx, cancel := context.WithTimeout(ctx, readyTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.URL+"/_ready", http.NoBody)
	if err != nil {
		return Readiness{State: "unreachable", Detail: err.Error()}
	}
	res, err := e.HTTP.Do(req)
	if err != nil {
		return Readiness{State: "unreachable", Detail: "no answer from " + e.URL}
	}
	defer func() { _ = res.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, maxErrorBody))
	if res.StatusCode != http.StatusOK {
		return Readiness{
			State:  "not ready",
			Detail: fmt.Sprintf("/_ready answered %d", res.StatusCode),
		}
	}
	return Readiness{State: "ready"}
}
