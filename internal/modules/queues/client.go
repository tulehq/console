package queues

import (
	"context"
	"net/http"
	"net/url"

	"github.com/aws/aws-sdk-go-v2/aws"

	"tule.dev/console/internal/awsclient"
)

// signingName is the service the inspection API is signed for, as the SQS
// API is.
const signingName = "sqs"

// Counts are a queue's messages by state.
type Counts struct {
	Visible  int `json:"visible"`
	InFlight int `json:"inFlight"`
	Delayed  int `json:"delayed"`
}

// Queue is a queue as GET /_queues/queues answers it.
type Queue struct {
	Attributes map[string]string `json:"attributes"`
	Name       string            `json:"name"`
	URL        string            `json:"url"`
	ARN        string            `json:"arn"`
	Counts     Counts            `json:"counts"`
}

// MessageAttribute is a message attribute; a Binary one's value is base64.
type MessageAttribute struct {
	DataType    string `json:"dataType"`
	StringValue string `json:"stringValue"`
	BinaryValue string `json:"binaryValue"`
}

// Message is a message as the inspection API answers it.
type Message struct {
	Attributes        map[string]string           `json:"attributes"`
	MessageAttributes map[string]MessageAttribute `json:"messageAttributes"`
	ID                string                      `json:"id"`
	Body              string                      `json:"body"`
	SentTime          string                      `json:"sentTime"`
	State             string                      `json:"state"`
	VisibleAt         string                      `json:"visibleAt"`
	Group             string                      `json:"group"`
	DeduplicationID   string                      `json:"deduplicationId"`
	SequenceNumber    string                      `json:"sequenceNumber"`
	ReceiveCount      int                         `json:"receiveCount"`
}

// MessagePage is a page of a queue's messages.
type MessagePage struct {
	NextCursor string    `json:"nextCursor"`
	Items      []Message `json:"items"`
}

// Inspector is the inspection API the section calls; *Inspection is one.
type Inspector interface {
	Queues(ctx context.Context) ([]Queue, error)
	Messages(ctx context.Context, queue string, query url.Values) (MessagePage, error)
}

// Inspection calls queues' inspection API under /_queues/.
type Inspection struct {
	signed *awsclient.Signed
}

// NewInspection returns a client of e's inspection API signed with creds.
func NewInspection(e awsclient.Endpoint, creds aws.Credentials) *Inspection {
	return &Inspection{signed: awsclient.NewSigned(e, signingName, creds)}
}

// Queues lists every queue with its counts and attributes.
func (c *Inspection) Queues(ctx context.Context) ([]Queue, error) {
	var out struct {
		Items []Queue `json:"items"`
	}
	err := c.signed.JSON(ctx, http.MethodGet, c.signed.URL(nil, "_queues", "queues"), &out)
	return out.Items, err
}

// Messages lists a page of queue's messages matching query, without
// changing them.
func (c *Inspection) Messages(
	ctx context.Context,
	queue string,
	query url.Values,
) (MessagePage, error) {
	var p MessagePage
	err := c.signed.JSON(
		ctx,
		http.MethodGet,
		c.signed.URL(query, "_queues", "queues", queue, "messages"),
		&p,
	)
	return p, err
}
