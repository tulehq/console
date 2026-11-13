package mail

import (
	"context"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"

	"tule.dev/console/internal/awsclient"
)

// signingName is the service the retrieval API is signed for, as the SES
// API is.
const signingName = "ses"

// NameValue is a tag or a header.
type NameValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Summary is a listed message, as GET /_mailbox/messages answers it.
type Summary struct {
	Time             string      `json:"time"`
	ID               string      `json:"id"`
	From             string      `json:"from"`
	Subject          string      `json:"subject"`
	ConfigurationSet string      `json:"configurationSet"`
	To               []string    `json:"to"`
	Cc               []string    `json:"cc"`
	Bcc              []string    `json:"bcc"`
	Tags             []NameValue `json:"tags"`
	Size             int64       `json:"size"`
	AttachmentCount  int         `json:"attachmentCount"`
}

// Attachment is an attachment's metadata.
type Attachment struct {
	Name        string `json:"name"`
	ContentType string `json:"contentType"`
	Size        int64  `json:"size"`
}

// Message is a message in full.
type Message struct {
	Text        string       `json:"text"`
	HTML        string       `json:"html"`
	Headers     []NameValue  `json:"headers"`
	Attachments []Attachment `json:"attachments"`
	Summary
}

// Page is a page of messages.
type Page struct {
	NextCursor string    `json:"nextCursor"`
	Items      []Summary `json:"items"`
}

// Failure is a rendering failure.
type Failure struct {
	MessageID        string      `json:"messageId"`
	Time             string      `json:"time"`
	Source           string      `json:"source"`
	Template         string      `json:"template"`
	From             string      `json:"from"`
	ConfigurationSet string      `json:"configurationSet"`
	Error            string      `json:"error"`
	To               []string    `json:"to"`
	Cc               []string    `json:"cc"`
	Bcc              []string    `json:"bcc"`
	Tags             []NameValue `json:"tags"`
}

// FailurePage is a page of rendering failures.
type FailurePage struct {
	NextCursor string    `json:"nextCursor"`
	Items      []Failure `json:"items"`
}

// Body is a streamed answer: its bytes, the type the service gave them,
// and the file name of its Content-Disposition, "" when it sent none.
type Body struct {
	Reader      io.ReadCloser
	ContentType string
	FileName    string
	Length      int64
}

// API is the retrieval API the section calls; *Client is one.
type API interface {
	Messages(ctx context.Context, query url.Values) (Page, error)
	Message(ctx context.Context, id string) (Message, error)
	Raw(ctx context.Context, id string) (Body, error)
	Attachment(ctx context.Context, id string, index int) (Body, error)
	Delete(ctx context.Context, id string) error
	Reset(ctx context.Context) error
	Failures(ctx context.Context, query url.Values) (FailurePage, error)
}

// Client calls mailbox's retrieval API under /_mailbox/.
type Client struct {
	signed *awsclient.Signed
}

// NewClient returns a client of e's retrieval API signed with creds.
func NewClient(e awsclient.Endpoint, creds aws.Credentials) *Client {
	return &Client{signed: awsclient.NewSigned(e, signingName, creds)}
}

// Messages lists messages matching query.
func (c *Client) Messages(ctx context.Context, query url.Values) (Page, error) {
	var p Page
	err := c.signed.JSON(ctx, http.MethodGet, c.signed.URL(query, "_mailbox", "messages"), &p)
	return p, err
}

// Message returns the message id in full.
func (c *Client) Message(ctx context.Context, id string) (Message, error) {
	var m Message
	err := c.signed.JSON(ctx, http.MethodGet, c.signed.URL(nil, "_mailbox", "messages", id), &m)
	return m, err
}

// Raw returns the message's MIME.
func (c *Client) Raw(ctx context.Context, id string) (Body, error) {
	return c.body(ctx, c.signed.URL(nil, "_mailbox", "messages", id, "raw"))
}

// Attachment returns the attachment at index of the message.
func (c *Client) Attachment(ctx context.Context, id string, index int) (Body, error) {
	return c.body(
		ctx,
		c.signed.URL(nil, "_mailbox", "messages", id, "attachments", strconv.Itoa(index)),
	)
}

func (c *Client) body(ctx context.Context, u string) (Body, error) {
	//nolint:bodyclose // the caller closes Body.Reader
	res, err := c.signed.Do(ctx, http.MethodGet, u)
	if err != nil {
		return Body{}, err
	}
	var name string
	if _, params, perr := mime.ParseMediaType(res.Header.Get("Content-Disposition")); perr == nil {
		name = params["filename"]
	}
	return Body{
		Reader:      res.Body,
		ContentType: res.Header.Get("Content-Type"),
		FileName:    name,
		Length:      res.ContentLength,
	}, nil
}

// Delete deletes one message.
func (c *Client) Delete(ctx context.Context, id string) error {
	return c.signed.JSON(ctx, http.MethodDelete, c.signed.URL(nil, "_mailbox", "messages", id), nil)
}

// Reset deletes every message and every rendering failure.
func (c *Client) Reset(ctx context.Context) error {
	return c.signed.JSON(ctx, http.MethodDelete, c.signed.URL(nil, "_mailbox", "messages"), nil)
}

// Failures lists rendering failures matching query.
func (c *Client) Failures(ctx context.Context, query url.Values) (FailurePage, error) {
	var p FailurePage
	err := c.signed.JSON(
		ctx,
		http.MethodGet,
		c.signed.URL(query, "_mailbox", "rendering-failures"),
		&p,
	)
	if err != nil {
		return FailurePage{}, fmt.Errorf("list rendering failures: %w", err)
	}
	return p, nil
}
