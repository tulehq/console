package functions_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"

	"tule.dev/console/internal/consoletest"
)

const arnPrefix = "arn:aws:lambda:us-east-1:000000000000:function:"

// checkRevision refuses a RevisionId that is not the policy's, and moves
// the revision on for a change.
func (f *fakeLambda) checkRevision(rev *string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if rev != nil && *rev != strconv.Itoa(f.revision) {
		return consoletest.ServiceError(
			http.StatusPreconditionFailed,
			"PreconditionFailedException",
			"The Revision Id provided does not match the latest Revision Id.",
		)
	}
	f.revision++
	return nil
}

func (f *fakeLambda) GetPolicy(
	_ context.Context, in *lambda.GetPolicyInput, _ ...func(*lambda.Options),
) (*lambda.GetPolicyOutput, error) {
	doc, ok, err := f.policies.Get(*in.FunctionName)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, consoletest.ServiceError(http.StatusNotFound, "ResourceNotFoundException",
			"The resource you requested does not exist.")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return &lambda.GetPolicyOutput{
		Policy: aws.String(doc), RevisionId: aws.String(strconv.Itoa(f.revision)),
	}, nil
}

func (f *fakeLambda) PutResourcePolicy(
	_ context.Context, in *lambda.PutResourcePolicyInput, _ ...func(*lambda.Options),
) (*lambda.PutResourcePolicyOutput, error) {
	if err := f.checkRevision(in.RevisionId); err != nil {
		return nil, err
	}
	name := strings.TrimPrefix(*in.ResourceArn, arnPrefix)
	err := f.policies.Put(name, *in.Policy, "InvalidParameterValueException")
	return &lambda.PutResourcePolicyOutput{}, err
}

func (f *fakeLambda) DeleteResourcePolicy(
	_ context.Context, in *lambda.DeleteResourcePolicyInput, _ ...func(*lambda.Options),
) (*lambda.DeleteResourcePolicyOutput, error) {
	if err := f.checkRevision(in.RevisionId); err != nil {
		return nil, err
	}
	return &lambda.DeleteResourcePolicyOutput{},
		f.policies.Delete(strings.TrimPrefix(*in.ResourceArn, arnPrefix))
}

func (f *fakeLambda) RemovePermission(
	_ context.Context, in *lambda.RemovePermissionInput, _ ...func(*lambda.Options),
) (*lambda.RemovePermissionOutput, error) {
	if err := f.checkRevision(in.RevisionId); err != nil {
		return nil, err
	}
	doc, _, err := f.policies.Get(*in.FunctionName)
	if err != nil {
		return nil, err
	}
	var p map[string]any
	_ = json.Unmarshal([]byte(doc), &p)
	sts, _ := p["Statement"].([]any)
	kept := []any{}
	for _, st := range sts {
		if st.(map[string]any)["Sid"] != *in.StatementId {
			kept = append(kept, st)
		}
	}
	if len(kept) == len(sts) {
		return nil, consoletest.ServiceError(http.StatusNotFound, "ResourceNotFoundException",
			"No policy is associated with the given resource.")
	}
	if len(kept) == 0 {
		return &lambda.RemovePermissionOutput{}, f.policies.Delete(*in.FunctionName)
	}
	p["Statement"] = kept
	b, _ := json.Marshal(p)
	return &lambda.RemovePermissionOutput{},
		f.policies.Put(*in.FunctionName, string(b), "InvalidParameterValueException")
}

const invokePolicy = `{"Version":"2012-10-17","Id":"default","Statement":[` +
	`{"Sid":"partner","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},` +
	`"Action":"lambda:InvokeFunction","Resource":"` + arnPrefix + `echo"},` +
	`{"Sid":"sns","Effect":"Allow","Principal":{"Service":"sns.amazonaws.com"},` +
	`"Action":"lambda:InvokeFunction","Resource":"` + arnPrefix + `echo",` +
	`"Condition":{"ArnLike":{"AWS:SourceArn":"arn:aws:sns:us-east-1:000000000000:t"}}}]}`

func TestFunctionPolicy(t *testing.T) {
	f := newFake()
	f.add("echo")
	b := start(t, f)

	res := b.Get("/lambda/function?name=echo")
	consoletest.RequireText(t, res, "Policy", "No policy.")

	bad := `{"Statement":[{"Effect":"Allow","Action":"lambda:InvokeFunction"}]}`
	res = b.PostForm("/lambda/function/policy", url.Values{
		"name": {"echo"}, "arn": {arnPrefix + "echo"}, "document": {bad},
	})
	consoletest.RequireStatus(t, res, http.StatusBadRequest)
	consoletest.RequireText(
		t,
		res,
		"The service answered InvalidParameterValueException.",
		"Invoke",
	)
	if consoletest.Find(res.Doc, consoletest.ByID("function-policy-error")) == nil {
		t.Fatal("the refusal is not next to the form")
	}

	res = b.PostForm("/lambda/function/policy", url.Values{
		"name": {"echo"}, "arn": {arnPrefix + "echo"}, "document": {invokePolicy},
	})
	page := b.Get(res.Location())
	consoletest.RequireFlash(t, page, "ok", "Saved the policy of function echo.")
	consoletest.RequireText(t, page, "Statements", "partner", "sns.amazonaws.com", "AWS:SourceArn")
	rev := revisionOf(t, page)

	// A revision that is no longer the policy's is refused in place.
	res = b.PostForm("/lambda/function/permission/remove", url.Values{
		"name": {"echo"}, "statementId": {"partner"}, "revision": {"stale"},
	})
	consoletest.RequireStatus(t, res, http.StatusPreconditionFailed)
	consoletest.RequireText(t, res, "PreconditionFailedException")

	res = b.PostForm("/lambda/function/permission/remove", url.Values{
		"name": {"echo"}, "statementId": {"partner"}, "revision": {rev},
	})
	page = b.Get(res.Location())
	consoletest.RequireFlash(
		t,
		page,
		"ok",
		"Removed statement partner from the policy of function echo.",
	)
	if doc, _, _ := f.policies.Get("echo"); strings.Contains(doc, "partner") {
		t.Fatalf("the statement is still there: %s", doc)
	}

	rev = revisionOf(t, page)
	res = b.PostForm("/lambda/function/policy/delete", url.Values{
		"name": {"echo"}, "arn": {arnPrefix + "echo"}, "revision": {rev},
	})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Deleted the policy of function echo.")
	if _, ok, _ := f.policies.Get("echo"); ok {
		t.Fatal("the policy was not deleted")
	}
}

func TestFunctionPolicyDenied(t *testing.T) {
	f := newFake()
	f.add("echo")
	f.policies.Denied = consoletest.ServiceError(http.StatusForbidden, "AccessDeniedException",
		"User: arn:aws:iam::000000000000:user/dev is not authorized to perform: lambda:GetPolicy")
	b := start(t, f)
	res := b.Get("/lambda/function?name=echo")
	consoletest.RequireStatus(t, res, http.StatusOK)
	consoletest.RequireText(t, res, "Invoke", "The policy could not be read.",
		"The service answered AccessDeniedException.", "lambda:GetPolicy")
}

// revisionOf returns the RevisionId the page's policy forms send.
func revisionOf(t *testing.T, page *consoletest.Response) string {
	t.Helper()
	rev, _ := consoletest.Attr(consoletest.Find(page.Doc, consoletest.ByName("revision")), "value")
	if rev == "" {
		t.Fatal("the page sends no RevisionId")
	}
	return rev
}
