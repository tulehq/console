package secrets_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"

	"tule.dev/console/internal/consoletest"
)

// broad reports whether doc grants "Principal": "*", the fake's rule for a
// policy that grants broad access.
func broad(doc string) bool {
	var buf bytes.Buffer
	if json.Compact(&buf, []byte(doc)) != nil {
		return false
	}
	return strings.Contains(buf.String(), `"Principal":"*"`)
}

func (f *fakeSM) GetResourcePolicy(
	_ context.Context,
	in *secretsmanager.GetResourcePolicyInput,
	_ ...func(*secretsmanager.Options),
) (*secretsmanager.GetResourcePolicyOutput, error) {
	doc, ok, err := f.policies.Get(*in.SecretId)
	if err != nil {
		return nil, err
	}
	out := &secretsmanager.GetResourcePolicyOutput{Name: in.SecretId}
	if ok {
		out.ResourcePolicy = aws.String(doc)
	}
	return out, nil
}

func (f *fakeSM) PutResourcePolicy(
	_ context.Context,
	in *secretsmanager.PutResourcePolicyInput,
	_ ...func(*secretsmanager.Options),
) (*secretsmanager.PutResourcePolicyOutput, error) {
	f.mu.Lock()
	f.puts = append(f.puts, in)
	f.mu.Unlock()
	if aws.ToBool(in.BlockPublicPolicy) && broad(*in.ResourcePolicy) {
		return nil, consoletest.ServiceError(
			http.StatusBadRequest,
			"PublicPolicyException",
			"The BlockPublicPolicy parameter is set to true, and the resource policy grants broad access.",
		)
	}
	err := f.policies.Put(*in.SecretId, *in.ResourcePolicy, "MalformedPolicyDocumentException")
	if err != nil {
		return nil, err
	}
	return &secretsmanager.PutResourcePolicyOutput{Name: in.SecretId}, nil
}

func (f *fakeSM) DeleteResourcePolicy(
	_ context.Context,
	in *secretsmanager.DeleteResourcePolicyInput,
	_ ...func(*secretsmanager.Options),
) (*secretsmanager.DeleteResourcePolicyOutput, error) {
	return &secretsmanager.DeleteResourcePolicyOutput{}, f.policies.Delete(*in.SecretId)
}

func (f *fakeSM) ValidateResourcePolicy(
	_ context.Context,
	in *secretsmanager.ValidateResourcePolicyInput,
	_ ...func(*secretsmanager.Options),
) (*secretsmanager.ValidateResourcePolicyOutput, error) {
	if msg := consoletest.Malformed(*in.ResourcePolicy); msg != "" {
		return nil, consoletest.ServiceError(
			http.StatusBadRequest,
			"MalformedPolicyDocumentException",
			msg,
		)
	}
	out := &secretsmanager.ValidateResourcePolicyOutput{PolicyValidationPassed: true}
	if broad(*in.ResourcePolicy) {
		out.PolicyValidationPassed = false
		out.ValidationErrors = []types.ValidationErrorsEntry{
			{
				CheckName: aws.String(
					"BROAD_ACCESS",
				),
				ErrorMessage: aws.String("The policy grants broad access."),
			},
		}
	}
	return out, nil
}

const accountPolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
	`"Principal":{"AWS":"111122223333"},"Action":"secretsmanager:GetSecretValue","Resource":"*"}]}`

const publicPolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
	`"Principal":"*","Action":"secretsmanager:GetSecretValue","Resource":"*"}]}`

func TestSecretPolicy(t *testing.T) {
	f := newFake()
	f.add("db/password", "", "s3cret")
	b := start(t, f)

	res := b.Get("/secrets/secret?id=db/password")
	consoletest.RequireText(t, res, "Resource policy", "No policy.")
	box := consoletest.Find(res.Doc, consoletest.ByName("blockPublic"))
	if _, checked := consoletest.Attr(box, "checked"); box == nil || !checked {
		t.Fatal("the block public policy box is not there, checked")
	}

	// BlockPublicPolicy refuses the public policy, next to the form.
	res = b.PostForm("/secrets/secret/policy", url.Values{
		"id": {"db/password"}, "document": {publicPolicy}, "blockPublic": {"on"},
	})
	consoletest.RequireStatus(t, res, http.StatusBadRequest)
	consoletest.RequireText(t, res, "PublicPolicyException")
	if consoletest.Find(res.Doc, consoletest.ByID("secret-policy-error")) == nil {
		t.Fatal("the refusal is not next to the form")
	}

	res = b.PostForm("/secrets/secret/policy", url.Values{
		"id": {"db/password"}, "document": {accountPolicy}, "blockPublic": {"on"},
	})
	page := b.Get(res.Location())
	consoletest.RequireFlash(t, page, "ok", "Saved the resource policy of secret db/password.")
	consoletest.RequireText(t, page, `"Action": "secretsmanager:GetSecretValue"`)
	if last := f.puts[len(f.puts)-1]; !aws.ToBool(last.BlockPublicPolicy) {
		t.Fatal("BlockPublicPolicy was not sent")
	}

	res = b.PostForm("/secrets/secret/policy/delete", url.Values{"id": {"db/password"}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Deleted the resource policy")
	if _, ok, _ := f.policies.Get("db/password"); ok {
		t.Fatal("the policy was not deleted")
	}
}

func TestSecretPolicyValidate(t *testing.T) {
	f := newFake()
	f.add("db/password", "", "s3cret")
	b := start(t, f)

	// Validate shows the findings and keeps the document; nothing is stored.
	res := b.PostForm("/secrets/secret/policy/validate", url.Values{
		"id": {"db/password"}, "document": {publicPolicy}, "blockPublic": {"on"},
	})
	consoletest.RequireStatus(t, res, http.StatusOK)
	consoletest.RequireText(t, res, "The policy did not pass validation.", "BROAD_ACCESS",
		"The policy grants broad access.")
	if got := consoletest.Text(
		consoletest.Find(res.Doc, consoletest.ByName("document")),
	); got != publicPolicy {
		t.Fatalf("the form holds %q after validating", got)
	}
	if _, ok, _ := f.policies.Get("db/password"); ok {
		t.Fatal("validating stored the policy")
	}
	res = b.PostForm("/secrets/secret/policy/validate", url.Values{
		"id": {"db/password"}, "document": {accountPolicy},
	})
	consoletest.RequireText(t, res, "The policy passed validation.")
	box := consoletest.Find(res.Doc, consoletest.ByName("blockPublic"))
	if _, checked := consoletest.Attr(box, "checked"); checked {
		t.Fatal("the box is checked though it was posted unchecked")
	}
	res = b.PostForm("/secrets/secret/policy/validate", url.Values{
		"id": {"db/password"}, "document": {`{"Statement":[{"Effect":"Allow"}]}`},
	})
	consoletest.RequireStatus(t, res, http.StatusBadRequest)
	consoletest.RequireText(
		t,
		res,
		"MalformedPolicyDocumentException",
		"Missing required field Principal.",
	)
}

func TestSecretPolicyDenied(t *testing.T) {
	f := newFake()
	f.add("db/password", "", "s3cret")
	f.policies.Denied = consoletest.Denied(http.StatusBadRequest, "AccessDeniedException",
		"secretsmanager:GetResourcePolicy")
	b := start(t, f)
	res := b.Get("/secrets/secret?id=db/password")
	consoletest.RequireStatus(t, res, http.StatusOK)
	consoletest.RequireText(t, res, "Versions", "The policy could not be read.",
		"The service answered AccessDeniedException.",
		"is not authorized to perform: secretsmanager:GetResourcePolicy")
}
