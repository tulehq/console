package objects_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"

	"tule.dev/console/internal/consoletest"
	"tule.dev/console/internal/web"
)

func (f *fakeS3) GetBucketPolicy(
	_ context.Context, in *s3.GetBucketPolicyInput, _ ...func(*s3.Options),
) (*s3.GetBucketPolicyOutput, error) {
	doc, ok, err := f.policies.Get(*in.Bucket)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, &smithy.GenericAPIError{
			Code: "NoSuchBucketPolicy", Message: "The bucket policy does not exist",
		}
	}
	return &s3.GetBucketPolicyOutput{Policy: aws.String(doc)}, nil
}

func (f *fakeS3) PutBucketPolicy(
	_ context.Context, in *s3.PutBucketPolicyInput, _ ...func(*s3.Options),
) (*s3.PutBucketPolicyOutput, error) {
	return &s3.PutBucketPolicyOutput{}, f.policies.Put(*in.Bucket, *in.Policy, "MalformedPolicy")
}

func (f *fakeS3) DeleteBucketPolicy(
	_ context.Context, in *s3.DeleteBucketPolicyInput, _ ...func(*s3.Options),
) (*s3.DeleteBucketPolicyOutput, error) {
	return &s3.DeleteBucketPolicyOutput{}, f.policies.Delete(*in.Bucket)
}

const readPolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
	`"Principal":{"AWS":"111122223333"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::photos/*"}]}`

func TestBucketPolicy(t *testing.T) {
	f := newFake()
	f.buckets["photos"] = map[string]object{"a/b.txt": {body: []byte("x")}}
	b := start(t, f)

	res := b.Get("/s3/bucket?bucket=photos")
	consoletest.RequireText(t, res, "Policy", "No policy.")
	if consoletest.Find(res.Doc, consoletest.FormTo("/s3/bucket/policy/delete")) != nil {
		t.Fatal("a bucket without a policy offers to delete it")
	}
	// A prefix of the bucket does not repeat the section.
	res = b.Get("/s3/bucket?bucket=photos&prefix=a/")
	if consoletest.Find(res.Doc, consoletest.FormTo("/s3/bucket/policy")) != nil {
		t.Fatal("a prefix's page shows the policy")
	}

	// A malformed document is refused next to the form, as typed.
	bad := `{"Statement":[{"Effect":"Allow"}]}`
	res = b.PostForm("/s3/bucket/policy", url.Values{"bucket": {"photos"}, "document": {bad}})
	consoletest.RequireStatus(t, res, http.StatusBadRequest)
	consoletest.RequireText(t, res, "The service answered MalformedPolicy.",
		"Missing required field Principal.")
	if consoletest.Find(res.Doc, consoletest.ByID("bucket-policy-error")) == nil {
		t.Fatal("the refusal is not next to the form")
	}
	if got := consoletest.Text(
		consoletest.Find(res.Doc, consoletest.ByName("document")),
	); got != bad {
		t.Fatalf("the form holds %q, want the document as typed", got)
	}
	consoletest.RequireText(t, res, "a/", "Upload") // the rest of the page

	res = b.PostForm(
		"/s3/bucket/policy",
		url.Values{"bucket": {"photos"}, "document": {readPolicy}},
	)
	page := b.Get(res.Location())
	consoletest.RequireFlash(t, page, "ok", "Saved the policy of bucket photos.")
	consoletest.RequireText(t, page, `"Action": "s3:GetObject"`)
	if consoletest.Find(page.Doc, consoletest.FormTo("/s3/bucket/policy/delete")) == nil {
		t.Fatal("no delete for the stored policy")
	}

	res = b.PostForm("/s3/bucket/policy/delete", url.Values{
		"bucket": {"photos"}, "loaded": {web.PolicyVersion(readPolicy)},
	})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Deleted the policy of bucket photos.")
	if _, ok, _ := f.policies.Get("photos"); ok {
		t.Fatal("the policy was not deleted")
	}
}

func TestBucketPolicyDenied(t *testing.T) {
	f := newFake()
	f.buckets["photos"] = map[string]object{"b.txt": {body: []byte("x")}}
	f.policies.Denied = consoletest.AccessDenied("s3:GetBucketPolicy")
	b := start(t, f)

	res := b.Get("/s3/bucket?bucket=photos")
	consoletest.RequireStatus(t, res, http.StatusOK)
	consoletest.RequireText(t, res, "b.txt", "The policy could not be read.",
		"The service answered AccessDenied.", "is not authorized to perform: s3:GetBucketPolicy")

	f.policies.Denied = consoletest.AccessDenied("s3:PutBucketPolicy")
	res = b.PostForm(
		"/s3/bucket/policy",
		url.Values{"bucket": {"photos"}, "document": {readPolicy}},
	)
	consoletest.RequireStatus(t, res, http.StatusForbidden)
	consoletest.RequireText(t, res, "b.txt", "is not authorized to perform: s3:PutBucketPolicy")
	if consoletest.Find(res.Doc, consoletest.ByID("bucket-policy-error")) == nil {
		t.Fatal("the refusal is not next to the form")
	}
}

// TestBucketPolicyChangedSincePageLoaded refuses a save and a delete when
// the policy changed after the page read it, keeping the typed document
// and showing the stored one.
func TestBucketPolicyChangedSincePageLoaded(t *testing.T) {
	f := newFake()
	f.buckets["photos"] = map[string]object{}
	b := start(t, f)
	page := b.Get("/s3/bucket?bucket=photos")

	// Another client attaches a policy after the page was read.
	other := strings.Replace(readPolicy, "s3:GetObject", "s3:PutObject", 1)
	if err := f.policies.Put("photos", other, "MalformedPolicy"); err != nil {
		t.Fatal(err)
	}
	res := b.PostForm("/s3/bucket/policy", consoletest.Hidden(page,
		consoletest.FormTo("/s3/bucket/policy"), "document", readPolicy))
	consoletest.RequireStatus(t, res, http.StatusConflict)
	consoletest.RequireText(t, res, "The policy changed since the page was loaded",
		"The stored policy now", `"Action": "s3:PutObject"`)
	if got := consoletest.Text(
		consoletest.Find(res.Doc, consoletest.ByName("document")),
	); got != readPolicy {
		t.Fatalf("the form holds %q, want the typed document", got)
	}
	if doc, _, _ := f.policies.Get("photos"); doc != other {
		t.Fatalf("the change made since was overwritten: %s", doc)
	}

	// The refused page carries the policy as it is now: saving from it
	// replaces it, as asked.
	res = b.PostForm("/s3/bucket/policy", consoletest.Hidden(res,
		consoletest.FormTo("/s3/bucket/policy"), "document", readPolicy))
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Saved the policy")

	// A delete from a page read before the save is refused too.
	res = b.PostForm("/s3/bucket/policy/delete", url.Values{
		"bucket": {"photos"}, "loaded": {web.PolicyVersion(other)},
	})
	consoletest.RequireStatus(t, res, http.StatusConflict)
	if _, ok, _ := f.policies.Get("photos"); !ok {
		t.Fatal("the delete went through")
	}
}

// TestBucketPolicyRefusedUnknown shows a refused save whose policy cannot
// be read again as unknown, not as no policy, and keeps a refusal whose
// page cannot be shown again.
func TestBucketPolicyRefusedUnknown(t *testing.T) {
	f := newFake()
	f.buckets["photos"] = map[string]object{}
	f.policies.Denied = consoletest.AccessDenied("s3:GetBucketPolicy")
	b := start(t, f)
	res := b.PostForm(
		"/s3/bucket/policy",
		url.Values{"bucket": {"photos"}, "document": {readPolicy}},
	)
	consoletest.RequireStatus(t, res, http.StatusForbidden)
	consoletest.RequireText(t, res, "whether there is one is unknown", "s3:GetBucketPolicy")
	if strings.Contains(consoletest.Text(res.Doc), "No policy.") {
		t.Fatal("a policy that could not be read shows as none")
	}

	// The bucket is gone, so its page fails too: both are shown.
	f.policies.Denied = consoletest.AccessDenied("s3:PutBucketPolicy")
	res = b.PostForm("/s3/bucket/policy", url.Values{"bucket": {"gone"}, "document": {readPolicy}})
	consoletest.RequireStatus(t, res, http.StatusForbidden)
	consoletest.RequireText(t, res, "The policy was not changed", "s3:PutBucketPolicy",
		"The page could not be shown again", "NoSuchBucket")
}
