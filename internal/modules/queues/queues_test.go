package queues_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/smithy-go"

	"tule.dev/console/internal/app"
	"tule.dev/console/internal/awsclient"
	"tule.dev/console/internal/consoletest"
	"tule.dev/console/internal/modules/queues"
)

// fakeQueues is queues in memory, behind both the inspection API, served
// over HTTP, and the SQS client.
type fakeQueues struct {
	queues   map[string]*queues.Queue
	msgs     map[string][]queues.Message
	policies consoletest.PolicyStore
	sent     []*sqs.SendMessageInput
	created  []*sqs.CreateQueueInput
	purged   []string
	queries  []url.Values
	mu       sync.Mutex
}

func newFake() *fakeQueues {
	return &fakeQueues{queues: map[string]*queues.Queue{}, msgs: map[string][]queues.Message{}}
}

func (f *fakeQueues) add(name string, fifo bool) {
	attrs := map[string]string{
		"VisibilityTimeout": "30",
		"QueueArn":          "arn:aws:sqs:us-east-1:000000000000:" + name,
	}
	if fifo {
		attrs["FifoQueue"] = "true"
	}
	f.queues[name] = &queues.Queue{
		Name:       name,
		URL:        "http://queues/000000000000/" + name,
		ARN:        attrs["QueueArn"],
		Attributes: attrs,
	}
}

func (f *fakeQueues) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.Contains(r.Header.Get("Authorization"), "/sqs/aws4_request") {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path == "/_queues/queues" {
		var items []queues.Queue
		for _, q := range f.queues {
			items = append(items, *q)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"items": items})
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/_queues/queues/")
	if name, ok := strings.CutSuffix(rest, "/messages"); ok {
		f.queries = append(f.queries, r.URL.Query())
		_ = json.NewEncoder(w).Encode(queues.MessagePage{Items: f.msgs[name]})
		return
	}
	http.NotFound(w, r)
}

func noQueue() error {
	return &smithy.GenericAPIError{
		Code:    "AWS.SimpleQueueService.NonExistentQueue",
		Message: "The specified queue does not exist.",
	}
}

func (f *fakeQueues) CreateQueue(
	_ context.Context,
	in *sqs.CreateQueueInput,
	_ ...func(*sqs.Options),
) (*sqs.CreateQueueOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.created = append(f.created, in)
	f.add(*in.QueueName, in.Attributes["FifoQueue"] == "true")
	return &sqs.CreateQueueOutput{}, nil
}

//nolint:revive // the SDK's method name
func (f *fakeQueues) GetQueueUrl(
	_ context.Context,
	in *sqs.GetQueueUrlInput,
	_ ...func(*sqs.Options),
) (*sqs.GetQueueUrlOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	q, ok := f.queues[*in.QueueName]
	if !ok {
		return nil, noQueue()
	}
	return &sqs.GetQueueUrlOutput{QueueUrl: aws.String(q.URL)}, nil
}

func (f *fakeQueues) byURL(u string) string {
	for n, q := range f.queues {
		if q.URL == u {
			return n
		}
	}
	return ""
}

func (f *fakeQueues) DeleteQueue(
	_ context.Context,
	in *sqs.DeleteQueueInput,
	_ ...func(*sqs.Options),
) (*sqs.DeleteQueueOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.queues, f.byURL(*in.QueueUrl))
	return &sqs.DeleteQueueOutput{}, nil
}

func (f *fakeQueues) PurgeQueue(
	_ context.Context,
	in *sqs.PurgeQueueInput,
	_ ...func(*sqs.Options),
) (*sqs.PurgeQueueOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := f.byURL(*in.QueueUrl)
	f.purged = append(f.purged, n)
	delete(f.msgs, n)
	return &sqs.PurgeQueueOutput{}, nil
}

func (f *fakeQueues) SendMessage(
	_ context.Context,
	in *sqs.SendMessageInput,
	_ ...func(*sqs.Options),
) (*sqs.SendMessageOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, in)
	return &sqs.SendMessageOutput{MessageId: aws.String("msg-1")}, nil
}

func start(t *testing.T, f *fakeQueues) *consoletest.Browser {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	ep := awsclient.Endpoint{URL: srv.URL, Region: "us-east-1", HTTP: srv.Client()}
	s := consoletest.Start(t, app.Overrides{Queues: func(c aws.Credentials) queues.Clients {
		return queues.Clients{Inspect: queues.NewInspection(ep, c), SQS: f}
	}}, nil, "sqs")
	b := s.Browser(t)
	b.SignIn(consoletest.KeyID, consoletest.Secret)
	return b
}

func TestQueuesAndMessages(t *testing.T) {
	f := newFake()
	f.add("orders", false)
	f.queues["orders"].Counts = queues.Counts{Visible: 3, InFlight: 1, Delayed: 2}
	f.add("jobs.fifo", true)
	f.msgs["orders"] = []queues.Message{
		{
			ID:           "m-1",
			Body:         `{"order":42}`,
			State:        "inFlight",
			ReceiveCount: 1,
			SentTime:     "2026-11-13T03:08:29.572Z",
			VisibleAt:    "2026-11-13T03:08:59.590Z",
			Attributes:   map[string]string{"SenderId": "test"},
			MessageAttributes: map[string]queues.MessageAttribute{
				"kind": {DataType: "String", StringValue: "greeting"},
			},
		},
	}
	b := start(t, f)

	res := b.Get("/sqs")
	consoletest.RequireStatus(t, res, http.StatusOK)
	consoletest.RequireText(t, res, "orders", "jobs.fifo", "FIFO", "Standard")

	res = b.Get("/sqs/queue?name=orders&state=inFlight&group=g1")
	consoletest.RequireStatus(t, res, http.StatusOK)
	consoletest.RequireText(
		t,
		res,
		`{"order":42}`,
		"inFlight",
		"kind (String)",
		"greeting",
		"SenderId",
		"3 visible, 1 in flight, 2 delayed",
		"VisibilityTimeout",
	)
	q := f.queries[len(f.queries)-1]
	if q.Get("state") != "inFlight" || q.Get("group") != "g1" || q.Get("limit") != "50" {
		t.Fatalf("the inspection API got %v", q)
	}

	res = b.Get("/sqs/queue?name=missing")
	consoletest.RequireStatus(t, res, http.StatusNotFound)
}

func TestSend(t *testing.T) {
	f := newFake()
	f.add("jobs.fifo", true)
	b := start(t, f)
	page := b.Get("/sqs/queue?name=jobs.fifo")
	if consoletest.Find(page.Doc, consoletest.ByName("groupId")) == nil {
		t.Fatal("a FIFO queue's form has no group ID")
	}

	res := b.PostForm("/sqs/queue/send", url.Values{
		"name": {"jobs.fifo"}, "body": {"hello"}, "groupId": {"g"}, "dedupId": {"d"},
		"attributes": {"kind=greeting\nteam = growth=x\n"},
	})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Sent message msg-1.")
	in := f.sent[0]
	if *in.QueueUrl != f.queues["jobs.fifo"].URL || *in.MessageBody != "hello" ||
		*in.MessageGroupId != "g" || *in.MessageDeduplicationId != "d" ||
		*in.MessageAttributes["kind"].StringValue != "greeting" || *in.MessageAttributes["team"].StringValue != " growth=x" {
		t.Fatalf("sent %+v", in)
	}

	res = b.PostForm(
		"/sqs/queue/send",
		url.Values{"name": {"jobs.fifo"}, "body": {"x"}, "attributes": {"=novalue"}},
	)
	consoletest.RequireFlash(t, b.Get(res.Location()), "error", "is not Name=Value")
}

func TestPurgeCreateDelete(t *testing.T) {
	f := newFake()
	f.add("jobs.fifo", true)
	b := start(t, f)
	b.Get("/sqs/queue?name=jobs.fifo")

	res := b.PostForm("/sqs/queue/purge", url.Values{"name": {"jobs.fifo"}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Purged queue jobs.fifo.")

	res = b.PostForm(
		"/sqs/queues",
		url.Values{"name": {"events"}, "fifo": {"on"}, "contentDedup": {"on"}},
	)
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Created queue events.fifo.")
	c := f.created[0]
	if *c.QueueName != "events.fifo" || c.Attributes["FifoQueue"] != "true" ||
		c.Attributes["ContentBasedDeduplication"] != "true" {
		t.Fatalf("created %+v", c)
	}

	res = b.PostForm("/sqs/queue/delete", url.Values{"name": {"events.fifo"}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Deleted queue events.fifo.")
	if _, ok := f.queues["events.fifo"]; ok {
		t.Fatal("the queue was not deleted")
	}

	res = b.PostForm("/sqs/queue/purge", url.Values{"name": {"nope"}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "error", "does not exist")
}

func TestHostileQueuesRenderInert(t *testing.T) {
	f := newFake()
	for _, h := range consoletest.Hostile {
		f.add(h, false)
		f.queues[h].Attributes[h] = h
		f.msgs[h] = []queues.Message{
			{
				ID:              h,
				Body:            h,
				State:           h,
				Group:           h,
				DeduplicationID: h,
				Attributes:      map[string]string{h: h},
				MessageAttributes: map[string]queues.MessageAttribute{
					h: {DataType: h, StringValue: h},
				},
			},
		}
	}
	b := start(t, f)
	res := b.Get("/sqs")
	consoletest.RequireInert(t, res)
	consoletest.RequireText(t, res, consoletest.Hostile...)
	for _, h := range consoletest.Hostile {
		res = b.Get("/sqs/queue?name=" + url.QueryEscape(h))
		consoletest.RequireStatus(t, res, http.StatusOK)
		consoletest.RequireInert(t, res)
	}
}
