//go:build e2e

package e2e

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"

	"tule.dev/console/internal/awsclient"
	"tule.dev/console/internal/consoletest"
)

func visible(t *testing.T, sdk *sqs.Client, queueURL *string) string {
	t.Helper()
	out, err := sdk.GetQueueAttributes(t.Context(), &sqs.GetQueueAttributesInput{
		QueueUrl: queueURL,
		AttributeNames: []types.QueueAttributeName{
			types.QueueAttributeNameApproximateNumberOfMessages,
		},
	})
	requireNoErr(t, err, "get queue attributes")
	return out.Attributes["ApproximateNumberOfMessages"]
}

func TestQueues(t *testing.T) {
	b := rootBrowser(t)
	sdk := awsclient.SQS(endpoint("queues"), rootCreds)
	name := unique("orders-")

	b.Get("/sqs")
	res := b.PostForm("/sqs/queues", url.Values{"name": {name}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Created queue "+name)
	u, err := sdk.GetQueueUrl(t.Context(), &sqs.GetQueueUrlInput{QueueName: aws.String(name)})
	requireNoErr(t, err, "the created queue")

	res = b.PostForm(
		"/sqs/queue/send",
		url.Values{"name": {name}, "body": {`{"order":42}`}, "attributes": {"kind=greeting"}},
	)
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Sent message")
	if n := visible(t, sdk, u.QueueUrl); n != "1" {
		t.Fatalf("%s visible messages, want 1", n)
	}

	res = b.Get("/sqs/queue?name=" + name + "&state=visible")
	consoletest.RequireText(t, res, `{"order":42}`, "kind (String)", "greeting", "1 visible")
	recv, err := sdk.ReceiveMessage(
		t.Context(),
		&sqs.ReceiveMessageInput{QueueUrl: u.QueueUrl, VisibilityTimeout: 300},
	)
	requireNoErr(t, err, "receive")
	if len(recv.Messages) != 1 {
		t.Fatal("the message was not received")
	}
	res = b.Get("/sqs/queue?name=" + name + "&state=inFlight")
	consoletest.RequireText(t, res, `{"order":42}`, "inFlight")
	res = b.Get("/sqs/queue?name=" + name + "&state=visible")
	consoletest.RequireText(t, res, "No messages in this state.")

	res = b.PostForm("/sqs/queue/purge", url.Values{"name": {name}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Purged queue "+name)
	res = b.Get("/sqs/queue?name=" + name)
	consoletest.RequireText(t, res, "No messages in this state.")

	res = b.Get("/sqs")
	consoletest.RequireText(t, res, name)

	res = b.PostForm("/sqs/queue/delete", url.Values{"name": {name}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Deleted queue "+name)
	_, err = sdk.GetQueueUrl(t.Context(), &sqs.GetQueueUrlInput{QueueName: aws.String(name)})
	if err == nil {
		t.Fatal("the deleted queue is still there")
	}
}

func TestFIFOQueue(t *testing.T) {
	b := rootBrowser(t)
	sdk := awsclient.SQS(endpoint("queues"), rootCreds)
	name := unique("jobs-")

	b.Get("/sqs")
	res := b.PostForm("/sqs/queues", url.Values{"name": {name}, "fifo": {"on"}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Created queue "+name+".fifo")
	u, err := sdk.GetQueueUrl(
		t.Context(),
		&sqs.GetQueueUrlInput{QueueName: aws.String(name + ".fifo")},
	)
	requireNoErr(t, err, "the FIFO queue")

	page := b.Get("/sqs/queue?name=" + name + ".fifo")
	consoletest.RequireStatus(t, page, http.StatusOK)
	res = b.PostForm("/sqs/queue/send", url.Values{
		"name": {name + ".fifo"}, "body": {"step one"}, "groupId": {"g1"}, "dedupId": {"d1"},
	})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Sent message")

	res = b.Get("/sqs/queue?name=" + name + ".fifo&group=g1")
	consoletest.RequireText(t, res, "step one", "g1", "d1")
	res = b.Get("/sqs/queue?name=" + name + ".fifo&group=other")
	consoletest.RequireText(t, res, "No messages in this state.")

	recv, err := sdk.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: u.QueueUrl})
	requireNoErr(t, err, "receive")
	if len(recv.Messages) != 1 || aws.ToString(recv.Messages[0].Body) != "step one" {
		t.Fatalf("received %+v", recv.Messages)
	}

	// A FIFO send without a group is refused by queues, and the console says so.
	res = b.PostForm("/sqs/queue/send", url.Values{"name": {name + ".fifo"}, "body": {"x"}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "error", "The message was not sent")
}
