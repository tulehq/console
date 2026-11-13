package queues_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"tule.dev/console/internal/consoletest"
	"tule.dev/console/internal/web"
)

func (f *fakeQueues) name(u *string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.byURL(*u)
}

func (f *fakeQueues) GetQueueAttributes(
	_ context.Context, in *sqs.GetQueueAttributesInput, _ ...func(*sqs.Options),
) (*sqs.GetQueueAttributesOutput, error) {
	doc, ok, err := f.policies.Get(f.name(in.QueueUrl))
	if err != nil {
		return nil, err
	}
	out := &sqs.GetQueueAttributesOutput{Attributes: map[string]string{}}
	if ok {
		out.Attributes["Policy"] = doc
	}
	return out, nil
}

func (f *fakeQueues) SetQueueAttributes(
	_ context.Context, in *sqs.SetQueueAttributesInput, _ ...func(*sqs.Options),
) (*sqs.SetQueueAttributesOutput, error) {
	name := f.name(in.QueueUrl)
	doc := in.Attributes["Policy"]
	if doc == "" {
		return &sqs.SetQueueAttributesOutput{}, f.policies.Delete(name)
	}
	return &sqs.SetQueueAttributesOutput{}, f.policies.Put(name, doc, "InvalidAttributeValue")
}

func (f *fakeQueues) RemovePermission(
	_ context.Context, in *sqs.RemovePermissionInput, _ ...func(*sqs.Options),
) (*sqs.RemovePermissionOutput, error) {
	name := f.name(in.QueueUrl)
	doc, _, err := f.policies.Get(name)
	if err != nil {
		return nil, err
	}
	var p map[string]any
	_ = json.Unmarshal([]byte(doc), &p)
	sts, _ := p["Statement"].([]any)
	kept := []any{}
	for _, st := range sts {
		if st.(map[string]any)["Sid"] != *in.Label {
			kept = append(kept, st)
		}
	}
	if len(kept) == len(sts) {
		return nil, consoletest.ServiceError(http.StatusBadRequest, "InvalidParameterValue",
			"Value "+*in.Label+" for parameter Label is invalid. Reason: can't find label.")
	}
	if len(kept) == 0 {
		return &sqs.RemovePermissionOutput{}, f.policies.Delete(name)
	}
	p["Statement"] = kept
	b, _ := json.Marshal(p)
	return &sqs.RemovePermissionOutput{}, f.policies.Put(name, string(b), "InvalidAttributeValue")
}

const twoStatements = `{"Version":"2012-10-17","Statement":[` +
	`{"Sid":"send","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},` +
	`"Action":"SQS:SendMessage","Resource":"arn:aws:sqs:us-east-1:000000000000:orders"},` +
	`{"Sid":"read","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},` +
	`"Action":["SQS:ReceiveMessage","SQS:DeleteMessage"],"Resource":"arn:aws:sqs:us-east-1:000000000000:orders"}]}`

func TestQueuePolicy(t *testing.T) {
	f := newFake()
	f.add("orders", false)
	b := start(t, f)

	res := b.Get("/sqs/queue?name=orders")
	consoletest.RequireText(t, res, "Policy", "No policy.")

	bad := `{"Statement":[{"Effect":"Allow","Action":"sqs:*"}]}`
	res = b.PostForm("/sqs/queue/policy", url.Values{"name": {"orders"}, "document": {bad}})
	consoletest.RequireStatus(t, res, http.StatusBadRequest)
	consoletest.RequireText(t, res, "The service answered InvalidAttributeValue.", "Send a message")
	if got := consoletest.Text(
		consoletest.Find(res.Doc, consoletest.ByName("document")),
	); got != bad {
		t.Fatalf("the form holds %q", got)
	}

	res = b.PostForm(
		"/sqs/queue/policy",
		url.Values{"name": {"orders"}, "document": {twoStatements}},
	)
	page := b.Get(res.Location())
	consoletest.RequireFlash(t, page, "ok", "Saved the policy of queue orders.")
	consoletest.RequireText(t, page, "Statements", "send", "read",
		`["SQS:ReceiveMessage","SQS:DeleteMessage"]`)

	res = b.PostForm(
		"/sqs/queue/permission/remove",
		url.Values{"name": {"orders"}, "label": {"send"}},
	)
	page = b.Get(res.Location())
	consoletest.RequireFlash(
		t,
		page,
		"ok",
		"Removed statement send from the policy of queue orders.",
	)
	doc, _, _ := f.policies.Get("orders")
	if consoletest.Malformed(doc) != "" || len(mustStatements(t, doc)) != 1 {
		t.Fatalf("the policy after removing a statement: %s", doc)
	}

	res = b.PostForm(
		"/sqs/queue/permission/remove",
		url.Values{"name": {"orders"}, "label": {"gone"}},
	)
	consoletest.RequireStatus(t, res, http.StatusBadRequest)
	consoletest.RequireText(t, res, "InvalidParameterValue", "can't find label")

	res = b.PostForm("/sqs/queue/policy/delete", url.Values{
		"name": {"orders"}, "loaded": {web.PolicyVersion(doc)},
	})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Deleted the policy of queue orders.")
	if _, ok, _ := f.policies.Get("orders"); ok {
		t.Fatal("the policy was not deleted")
	}
}

func TestQueuePolicyDenied(t *testing.T) {
	f := newFake()
	f.add("orders", false)
	f.policies.Denied = consoletest.AccessDenied("sqs:getqueueattributes")
	b := start(t, f)
	res := b.Get("/sqs/queue?name=orders")
	consoletest.RequireStatus(t, res, http.StatusOK)
	consoletest.RequireText(t, res, "Send a message", "The policy could not be read.",
		"The service answered AccessDenied.")
}

func mustStatements(t *testing.T, doc string) []any {
	t.Helper()
	var p struct{ Statement []any }
	if err := json.Unmarshal([]byte(doc), &p); err != nil {
		t.Fatalf("policy %q: %v", doc, err)
	}
	return p.Statement
}

// TestQueuePolicyChangedSincePageLoaded refuses a save that would drop a
// statement AddPermission added after the page was read.
func TestQueuePolicyChangedSincePageLoaded(t *testing.T) {
	f := newFake()
	f.add("orders", false)
	b := start(t, f)
	page := b.Get("/sqs/queue?name=orders")
	if err := f.policies.Put("orders", twoStatements, "x"); err != nil {
		t.Fatal(err)
	}
	mine := `{"Statement":[{"Sid":"mine","Effect":"Allow","Principal":"*","Action":"sqs:*"}]}`
	res := b.PostForm("/sqs/queue/policy", consoletest.Hidden(page,
		consoletest.FormTo("/sqs/queue/policy"), "document", mine))
	consoletest.RequireStatus(t, res, http.StatusConflict)
	consoletest.RequireText(
		t,
		res,
		"The policy changed since the page was loaded",
		"The stored policy now",
	)
	if got := consoletest.Text(
		consoletest.Find(res.Doc, consoletest.ByName("document")),
	); got != mine {
		t.Fatalf("the form holds %q, want the typed document", got)
	}
	if doc, _, _ := f.policies.Get("orders"); doc != twoStatements {
		t.Fatalf("the statements added since were lost: %s", doc)
	}
	res = b.PostForm("/sqs/queue/policy/delete", consoletest.Hidden(page,
		consoletest.FormTo("/sqs/queue/policy")))
	consoletest.RequireStatus(t, res, http.StatusConflict)
}
