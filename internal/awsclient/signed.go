package awsclient

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// maxErrorBody bounds how much of an error response is read.
const maxErrorBody = 64 << 10

// maxJSONBody bounds a JSON answer of a retrieval API: a message in full,
// its text and HTML included, is the largest.
const maxJSONBody = 96 << 20

// APIError is an error answer of a retrieval or inspection API: its status
// and the {"code", "message"} body the services answer with.
type APIError struct {
	Code    string
	Message string
	Status  int
}

func (e *APIError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("status %d", e.Status)
	}
	return fmt.Sprintf("%s: %s (status %d)", e.Code, e.Message, e.Status)
}

// Signed calls a service's own JSON API, such as /_mailbox/, signing each
// request with SigV4 for the service's signing name, as its SDK API is.
type Signed struct {
	signer  *v4.Signer
	creds   aws.Credentials
	ep      Endpoint
	service string
}

// NewSigned returns a client of e's API signed for service with creds.
func NewSigned(e Endpoint, service string, creds aws.Credentials) *Signed {
	return &Signed{signer: v4.NewSigner(), creds: creds, ep: e, service: service}
}

// URL returns the absolute URL of the API path made of segments, each
// escaped as one path segment, and query.
func (c *Signed) URL(query url.Values, segments ...string) string {
	escaped := make([]string, len(segments))
	for i, s := range segments {
		escaped[i] = url.PathEscape(s)
	}
	u := c.ep.URL + "/" + strings.Join(escaped, "/")
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	return u
}

// Do sends a signed request without a body and returns the response. A
// response that is not 2xx is returned as an *APIError, its body read and
// closed.
func (c *Signed) Do(ctx context.Context, method, rawURL string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("build %s request: %w", method, err)
	}
	sum := sha256.Sum256(nil)
	if err = c.signer.SignHTTP(ctx, c.creds, req, hex.EncodeToString(sum[:]),
		c.service, c.ep.Region, time.Now()); err != nil {
		return nil, fmt.Errorf("sign %s request: %w", method, err)
	}
	res, err := c.ep.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, req.URL.Path, err)
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		defer func() { _ = res.Body.Close() }()
		return nil, readAPIError(res)
	}
	return res, nil
}

// JSON sends a signed request and decodes its JSON answer into out, which
// may be nil for an answer with no body.
func (c *Signed) JSON(ctx context.Context, method, rawURL string, out any) error {
	res, err := c.Do(ctx, method, rawURL)
	if err != nil {
		return err
	}
	defer func() { _ = res.Body.Close() }()
	if out == nil {
		_, err = io.Copy(io.Discard, io.LimitReader(res.Body, maxErrorBody))
		if err != nil {
			return fmt.Errorf("read %s answer: %w", method, err)
		}
		return nil
	}
	dec := json.NewDecoder(io.LimitReader(res.Body, maxJSONBody))
	if err = dec.Decode(out); err != nil {
		return fmt.Errorf("decode %s answer: %w", method, err)
	}
	return nil
}

func readAPIError(res *http.Response) error {
	body, err := io.ReadAll(io.LimitReader(res.Body, maxErrorBody))
	if err != nil {
		return fmt.Errorf("read error answer (status %d): %w", res.StatusCode, err)
	}
	e := &APIError{Status: res.StatusCode}
	var shape struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &shape) == nil {
		e.Code, e.Message = shape.Code, shape.Message
	}
	if e.Code == "" {
		e.Code, _, _ = strings.Cut(res.Header.Get("X-Amzn-ErrorType"), ":")
	}
	return e
}

// AsAPIError returns the *APIError err wraps.
func AsAPIError(err error) (*APIError, bool) {
	var e *APIError
	ok := errors.As(err, &e)
	return e, ok
}
