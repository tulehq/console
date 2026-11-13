package functions

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/aws/aws-sdk-go-v2/aws"

	"tule.dev/console/internal/awsclient"
)

// signingName is the service the retrieval API is signed for, as the
// Lambda API is.
const signingName = "lambda"

// Invocation is an invocation of the history, as GET
// /_functions/invocations answers it. The shape follows the functions
// design: the duration, payload and result are kept as the JSON the
// service gives, so the page shows them whatever their type.
type Invocation struct {
	RequestID    string          `json:"requestId"`
	Function     string          `json:"function"`
	Time         string          `json:"time"`
	Source       string          `json:"source"`
	Status       string          `json:"status"`
	ErrorType    string          `json:"errorType"`
	ErrorMessage string          `json:"errorMessage"`
	Log          string          `json:"log"`
	Duration     json.RawMessage `json:"duration"`
	Payload      json.RawMessage `json:"payload"`
	Result       json.RawMessage `json:"result"`
	Attempts     int             `json:"attempts"`
}

// InvocationPage is a page of the history.
type InvocationPage struct {
	NextCursor string       `json:"nextCursor"`
	Items      []Invocation `json:"items"`
}

// History is the retrieval API the section calls; *Retrieval is one.
type History interface {
	Invocations(ctx context.Context, query url.Values) (InvocationPage, error)
	Invocation(ctx context.Context, requestID string) (Invocation, error)
}

// Retrieval calls functions' retrieval API under /_functions/.
type Retrieval struct {
	signed *awsclient.Signed
}

// NewRetrieval returns a client of e's retrieval API signed with creds.
func NewRetrieval(e awsclient.Endpoint, creds aws.Credentials) *Retrieval {
	return &Retrieval{signed: awsclient.NewSigned(e, signingName, creds)}
}

// Invocations lists invocations matching query, newest first.
func (c *Retrieval) Invocations(ctx context.Context, query url.Values) (InvocationPage, error) {
	var p InvocationPage
	err := c.signed.JSON(ctx, http.MethodGet, c.signed.URL(query, "_functions", "invocations"), &p)
	return p, err
}

// Invocation returns one invocation with its payload, result and log.
func (c *Retrieval) Invocation(ctx context.Context, requestID string) (Invocation, error) {
	var inv Invocation
	err := c.signed.JSON(
		ctx,
		http.MethodGet,
		c.signed.URL(nil, "_functions", "invocations", requestID),
		&inv,
	)
	return inv, err
}
