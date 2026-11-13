//go:build e2e

package e2e

import (
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"tule.dev/console/internal/awsclient"
	"tule.dev/console/internal/consoletest"
)

// boundSection is a resource whose policy names a user: its page, the
// form that saves the policy, the id of its section, text of the rest of
// the page, the code the service refuses a principal that does not exist
// with, the policy granting principal, and the policy as stored.
type boundSection struct {
	put    func(doc string)
	stored func() string
	doc    func(principal string) string
	page   string
	save   string
	id     string
	rest   string
	code   string
}

// TestAPolicyNamingADeletedUser stores a policy naming a user on each
// resource, then deletes that IAM user: each Policy section shows its
// unique ID in place of its ARN, as the service's read shows it, and saves
// it again from the page unchanged. A save naming the deleted user's ARN,
// which no principal has any more, is refused next to the form.
func TestAPolicyNamingADeletedUser(t *testing.T) {
	ic := awsclient.IAM(endpoint("identity"), rootCreds)
	user := unique("named")
	out, err := ic.CreateUser(t.Context(), &iam.CreateUserInput{UserName: aws.String(user)})
	requireNoErr(t, err, "create user "+user)
	userARN, userID := aws.ToString(out.User.Arn), aws.ToString(out.User.UserId)
	if !strings.HasPrefix(userID, "AIDA") {
		t.Fatalf("the IAM user's ID is %q, want a unique ID", userID)
	}

	bucket, secret, queue, identity := resources(t)
	sections := []boundSection{
		bucketBound(t, bucket), secretBound(t, secret), queueBound(t, queue),
		identityBound(t, identity),
	}
	if fn.skip == "" {
		sections = append(sections, functionBound(t))
	}
	for _, s := range sections {
		s.put(s.doc(userARN))
	}

	_, err = ic.DeleteUser(t.Context(), &iam.DeleteUserInput{UserName: aws.String(user)})
	requireNoErr(t, err, "delete user "+user)

	b := rootBrowser(t)
	for _, s := range sections {
		page := b.Get(s.page)
		shown := textarea(t, page, s.id+"-document")
		if !strings.Contains(shown, userID) || strings.Contains(shown, userARN) {
			t.Fatalf("%s shows %s, want the deleted user's ID %s", s.page, shown, userID)
		}
		requireDocument(t, page, s.id, s.doc(userID))

		// Saved again as the page shows it, the policy still names the ID.
		form := consoletest.Hidden(page, consoletest.FormHolding(s.id+"-document"))
		form.Set("document", shown)
		res := b.PostForm(s.save, form)
		consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Saved")
		if got := s.stored(); mustCompact(t, got) != mustCompact(t, s.doc(userID)) {
			t.Fatalf("%s: stored %s, want %s", s.page, got, s.doc(userID))
		}

		// The deleted user's ARN names no principal, and is refused.
		page = b.Get(s.page)
		form = consoletest.Hidden(page, consoletest.FormHolding(s.id+"-document"))
		form.Set("document", s.doc(userARN))
		res = b.PostForm(s.save, form)
		requireRefused(t, res, s.id, s.code, s.doc(userARN), s.rest)
		if got := s.stored(); mustCompact(t, got) != mustCompact(t, s.doc(userID)) {
			t.Fatalf("%s: the refused save left %s", s.page, got)
		}
	}
}

// textarea returns the text of the page's textarea id as a browser would
// send it.
func textarea(t *testing.T, page *consoletest.Response, id string) string {
	t.Helper()
	n := consoletest.Find(page.Doc, consoletest.ByID(id))
	if n == nil || n.FirstChild == nil {
		t.Fatalf("no document in %s: %s", id, consoletest.Text(page.Doc))
	}
	return n.FirstChild.Data
}

// grantTo is a resource-based policy granting principal action on
// resource.
func grantTo(principal, action, resource string) string {
	return strings.Replace(grant("Named", action, resource), accountRoot, principal, 1)
}

func bucketBound(t *testing.T, bucket string) boundSection {
	t.Helper()
	sdk := s3Client()
	return boundSection{
		page: "/s3/bucket?bucket=" + bucket, save: "/s3/bucket/policy", id: "bucket-policy",
		rest: "Upload", code: "MalformedPolicy",
		doc: func(p string) string {
			return grantTo(p, "s3:GetObject", "arn:aws:s3:::"+bucket+"/*")
		},
		put: func(doc string) {
			_, err := sdk.PutBucketPolicy(t.Context(), &s3.PutBucketPolicyInput{
				Bucket: aws.String(bucket), Policy: aws.String(doc),
			})
			requireNoErr(t, err, "put the bucket policy")
		},
		stored: func() string {
			out, err := sdk.GetBucketPolicy(t.Context(),
				&s3.GetBucketPolicyInput{Bucket: aws.String(bucket)})
			requireNoErr(t, err, "get the bucket policy")
			return aws.ToString(out.Policy)
		},
	}
}

func secretBound(t *testing.T, secret string) boundSection {
	t.Helper()
	sdk := awsclient.SecretsManager(endpoint("secret-store"), rootCreds)
	return boundSection{
		page: "/secrets/secret?id=" + secret, save: "/secrets/secret/policy",
		id: "secret-policy", rest: "Versions", code: "MalformedPolicyDocumentException",
		doc: func(p string) string { return grantTo(p, "secretsmanager:GetSecretValue", "*") },
		put: func(doc string) {
			_, err := sdk.PutResourcePolicy(t.Context(), &secretsmanager.PutResourcePolicyInput{
				SecretId: aws.String(secret), ResourcePolicy: aws.String(doc),
			})
			requireNoErr(t, err, "put the secret's policy")
		},
		stored: func() string {
			out, err := sdk.GetResourcePolicy(t.Context(),
				&secretsmanager.GetResourcePolicyInput{SecretId: aws.String(secret)})
			requireNoErr(t, err, "get the secret's policy")
			return aws.ToString(out.ResourcePolicy)
		},
	}
}

func queueBound(t *testing.T, queue string) boundSection {
	t.Helper()
	sdk := awsclient.SQS(endpoint("queues"), rootCreds)
	q, err := sdk.GetQueueUrl(t.Context(), &sqs.GetQueueUrlInput{QueueName: aws.String(queue)})
	requireNoErr(t, err, "the queue's URL")
	return boundSection{
		page: "/sqs/queue?name=" + queue, save: "/sqs/queue/policy", id: "queue-policy",
		rest: "Send a message", code: "InvalidAttributeValue",
		doc: func(p string) string { return grantTo(p, "sqs:SendMessage", "*") },
		put: func(doc string) {
			_, err := sdk.SetQueueAttributes(t.Context(), &sqs.SetQueueAttributesInput{
				QueueUrl: q.QueueUrl, Attributes: map[string]string{"Policy": doc},
			})
			requireNoErr(t, err, "set the queue's policy")
		},
		stored: func() string { return queuePolicy(t, sdk, q.QueueUrl) },
	}
}

func identityBound(t *testing.T, identity string) boundSection {
	t.Helper()
	sdk := awsclient.SESv2(endpoint("mailbox"), rootCreds)
	arn := "arn:aws:ses:" + region + ":000000000000:identity/" + identity
	return boundSection{
		page: "/mail/identity?name=" + identity, save: "/mail/identity/policy",
		id: "policy-named-partner", rest: "Verification", code: "BadRequestException",
		doc: func(p string) string { return grantTo(p, "ses:SendEmail", arn) },
		put: func(doc string) {
			_, err := sdk.CreateEmailIdentityPolicy(t.Context(),
				&sesv2.CreateEmailIdentityPolicyInput{
					EmailIdentity: aws.String(identity), PolicyName: aws.String("partner"),
					Policy: aws.String(doc),
				})
			requireNoErr(t, err, "create the identity's policy")
		},
		stored: func() string {
			out, err := sdk.GetEmailIdentityPolicies(t.Context(),
				&sesv2.GetEmailIdentityPoliciesInput{EmailIdentity: aws.String(identity)})
			requireNoErr(t, err, "get the identity's policies")
			return out.Policies["partner"]
		},
	}
}

func functionBound(t *testing.T) boundSection {
	t.Helper()
	sdk := awsclient.Lambda(endpoint("functions"), rootCreds)
	name := unique("named-")
	createEcho(t, sdk, name)
	arn := "arn:aws:lambda:" + region + ":000000000000:function:" + name
	return boundSection{
		page: "/lambda/function?name=" + name, save: "/lambda/function/policy",
		id: "function-policy", rest: "Invoke", code: "InvalidParameterValueException",
		doc: func(p string) string { return grantTo(p, "lambda:InvokeFunction", arn) },
		put: func(doc string) {
			_, err := sdk.PutResourcePolicy(t.Context(), &lambda.PutResourcePolicyInput{
				ResourceArn: aws.String(arn), Policy: aws.String(doc),
			})
			requireNoErr(t, err, "put the function policy")
		},
		stored: func() string {
			out, err := sdk.GetPolicy(t.Context(),
				&lambda.GetPolicyInput{FunctionName: aws.String(name)})
			requireNoErr(t, err, "get the function policy")
			return aws.ToString(out.Policy)
		},
	}
}
