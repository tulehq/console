//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"

	"tule.dev/console/internal/awsclient"
	"tule.dev/console/internal/consoletest"
)

// accountRoot is the principal the resource policies of these tests grant:
// the root of the services' account.
const accountRoot = "arn:aws:iam::000000000000:root"

// grant is a resource-based policy granting accountRoot action on
// resource.
func grant(sid, action, resource string) string {
	return `{"Version":"2012-10-17","Statement":[{"Sid":"` + sid + `","Effect":"Allow",` +
		`"Principal":{"AWS":"` + accountRoot + `"},"Action":"` + action + `",` +
		`"Resource":"` + resource + `"}]}`
}

// noPrincipal is a document every service refuses: a resource-based
// policy needs a Principal.
const noPrincipal = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*",` +
	`"Resource":"*"}]}`

// requireRefused checks that res is the resource's page with the
// service's code next to the policy form id, which still holds doc, and
// the rest of the page, rest, around it.
func requireRefused(t *testing.T, res *consoletest.Response, id, code, doc, rest string) {
	t.Helper()
	if res.Status != http.StatusBadRequest && res.Status != http.StatusForbidden {
		t.Fatalf("status %d, want 400 or 403: %s", res.Status, consoletest.Text(res.Doc))
	}
	consoletest.RequireText(t, res, "The service answered "+code, rest)
	failure := consoletest.Find(res.Doc, consoletest.ByID(id+"-error"))
	if failure == nil {
		t.Fatalf("%s is not next to the form: %s", code, consoletest.Text(res.Doc))
	}
	if doc == "" {
		return
	}
	if got := consoletest.Text(
		consoletest.Find(res.Doc, consoletest.ByID(id+"-document")),
	); got != doc {
		t.Fatalf("the form holds %q, want the document as it was sent", got)
	}
}

// requireDocument checks that the page's policy form id holds doc,
// indented.
func requireDocument(t *testing.T, page *consoletest.Response, id, doc string) {
	t.Helper()
	text := consoletest.Text(consoletest.Find(page.Doc, consoletest.ByID(id+"-document")))
	if mustCompact(t, text) != mustCompact(t, doc) {
		t.Fatalf("the page shows %s, want %s", text, doc)
	}
	if !strings.Contains(string(page.Body), "{\n  &#34;Version&#34;: &#34;2012-10-17&#34;") {
		t.Fatal("the policy is not indented")
	}
}

func mustCompact(t *testing.T, doc string) string {
	t.Helper()
	var v any
	requireNoErr(t, json.Unmarshal([]byte(doc), &v), "the policy")
	b, err := json.Marshal(v)
	requireNoErr(t, err, "the policy")
	return string(b)
}

func TestABucketPolicy(t *testing.T) {
	b := rootBrowser(t)
	sdk := s3Client()
	bucket := unique("shared-")
	_, err := sdk.CreateBucket(t.Context(), &s3.CreateBucketInput{Bucket: aws.String(bucket)})
	requireNoErr(t, err, "create bucket")
	page := b.Get("/s3/bucket?bucket=" + bucket)
	consoletest.RequireText(t, page, "Policy", "No policy.")

	res := b.PostForm(
		"/s3/bucket/policy",
		url.Values{"bucket": {bucket}, "document": {noPrincipal}},
	)
	requireRefused(t, res, "bucket-policy", "MalformedPolicy", noPrincipal, "Upload")

	doc := grant("Read", "s3:GetObject", "arn:aws:s3:::"+bucket+"/*")
	res = b.PostForm("/s3/bucket/policy", url.Values{"bucket": {bucket}, "document": {doc}})
	page = b.Get(res.Location())
	consoletest.RequireFlash(t, page, "ok", "Saved the policy of bucket "+bucket)
	requireDocument(t, page, "bucket-policy", doc)
	got, err := sdk.GetBucketPolicy(
		t.Context(),
		&s3.GetBucketPolicyInput{Bucket: aws.String(bucket)},
	)
	requireNoErr(t, err, "get the bucket policy")
	if aws.ToString(got.Policy) != doc {
		t.Fatalf("stored %s, want %s", aws.ToString(got.Policy), doc)
	}

	res = b.PostForm("/s3/bucket/policy/delete", url.Values{"bucket": {bucket}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Deleted the policy of bucket "+bucket)
	_, err = sdk.GetBucketPolicy(t.Context(), &s3.GetBucketPolicyInput{Bucket: aws.String(bucket)})
	requireCode(t, err, "NoSuchBucketPolicy", "the deleted policy")
}

func TestASecretPolicy(t *testing.T) {
	b := rootBrowser(t)
	sdk := awsclient.SecretsManager(endpoint("secret-store"), rootCreds)
	name := unique("shared/")
	value := unique("value-")
	noteSecret(value)
	out, err := sdk.CreateSecret(t.Context(), &secretsmanager.CreateSecretInput{
		Name: aws.String(name), SecretString: aws.String(value),
	})
	requireNoErr(t, err, "create secret")
	arn := aws.ToString(out.ARN)
	form := func(doc string, block bool) url.Values {
		v := url.Values{"id": {name}, "document": {doc}}
		if block {
			v.Set("blockPublic", "on")
		}
		return v
	}

	res := b.PostForm("/secrets/secret/policy", form(noPrincipal, true))
	requireRefused(
		t,
		res,
		"secret-policy",
		"MalformedPolicyDocumentException",
		noPrincipal,
		"Versions",
	)

	// Validate reports broad access without storing anything, and
	// BlockPublicPolicy refuses that policy.
	public := strings.Replace(grant("Public", "secretsmanager:GetSecretValue", arn),
		`{"AWS":"`+accountRoot+`"}`, `"*"`, 1)
	res = b.PostForm("/secrets/secret/policy/validate", form(public, true))
	consoletest.RequireStatus(t, res, http.StatusOK)
	consoletest.RequireText(t, res, "The policy did not pass validation.", "BROAD_ACCESS")
	res = b.PostForm("/secrets/secret/policy", form(public, true))
	requireRefused(t, res, "secret-policy", "PublicPolicyException", public, "Versions")

	doc := grant("Read", "secretsmanager:GetSecretValue", arn)
	res = b.PostForm("/secrets/secret/policy/validate", form(doc, true))
	consoletest.RequireText(t, res, "The policy passed validation.")
	res = b.PostForm("/secrets/secret/policy", form(doc, true))
	page := b.Get(res.Location())
	consoletest.RequireFlash(t, page, "ok", "Saved the resource policy of secret "+name)
	requireDocument(t, page, "secret-policy", doc)
	got, err := sdk.GetResourcePolicy(t.Context(),
		&secretsmanager.GetResourcePolicyInput{SecretId: aws.String(name)})
	requireNoErr(t, err, "get the resource policy")
	if mustCompact(t, aws.ToString(got.ResourcePolicy)) != mustCompact(t, doc) {
		t.Fatalf("stored %s, want %s", aws.ToString(got.ResourcePolicy), doc)
	}

	res = b.PostForm("/secrets/secret/policy/delete", url.Values{"id": {name}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Deleted the resource policy")
	got, err = sdk.GetResourcePolicy(t.Context(),
		&secretsmanager.GetResourcePolicyInput{SecretId: aws.String(name)})
	requireNoErr(t, err, "get the deleted resource policy")
	if got.ResourcePolicy != nil {
		t.Fatalf("the policy is still there: %s", aws.ToString(got.ResourcePolicy))
	}
}

func TestAQueuePolicy(t *testing.T) {
	b := rootBrowser(t)
	sdk := awsclient.SQS(endpoint("queues"), rootCreds)
	name := unique("shared-")
	q, err := sdk.CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String(name)})
	requireNoErr(t, err, "create queue")
	arn := "arn:aws:sqs:" + region + ":000000000000:" + name

	res := b.PostForm("/sqs/queue/policy", url.Values{"name": {name}, "document": {noPrincipal}})
	requireRefused(t, res, "queue-policy", "InvalidAttributeValue", noPrincipal, "Send a message")

	// AddPermission's statement is listed, and removed by its label.
	_, err = sdk.AddPermission(t.Context(), &sqs.AddPermissionInput{
		QueueUrl: q.QueueUrl, Label: aws.String("partner"),
		AWSAccountIds: []string{"000000000000"}, Actions: []string{"SendMessage"},
	})
	requireNoErr(t, err, "add permission")
	page := b.Get("/sqs/queue?name=" + name)
	consoletest.RequireText(t, page, "Statements", "partner", "SQS:SendMessage")
	res = b.PostForm(
		"/sqs/queue/permission/remove",
		url.Values{"name": {name}, "label": {"partner"}},
	)
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Removed statement partner")
	if p := queuePolicy(t, sdk, q.QueueUrl); p != "" {
		t.Fatalf("the policy after removing its one statement: %s", p)
	}

	doc := grant("Send", "sqs:SendMessage", arn)
	res = b.PostForm("/sqs/queue/policy", url.Values{"name": {name}, "document": {doc}})
	page = b.Get(res.Location())
	consoletest.RequireFlash(t, page, "ok", "Saved the policy of queue "+name)
	requireDocument(t, page, "queue-policy", doc)
	if p := queuePolicy(t, sdk, q.QueueUrl); p != doc {
		t.Fatalf("stored %s, want %s", p, doc)
	}

	res = b.PostForm("/sqs/queue/policy/delete", url.Values{"name": {name}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Deleted the policy of queue "+name)
	if p := queuePolicy(t, sdk, q.QueueUrl); p != "" {
		t.Fatalf("the policy is still there: %s", p)
	}
}

func queuePolicy(t *testing.T, sdk *sqs.Client, u *string) string {
	t.Helper()
	out, err := sdk.GetQueueAttributes(t.Context(), &sqs.GetQueueAttributesInput{
		QueueUrl: u, AttributeNames: []types.QueueAttributeName{types.QueueAttributeNamePolicy},
	})
	requireNoErr(t, err, "get the queue's policy")
	return out.Attributes["Policy"]
}

func TestAFunctionPolicy(t *testing.T) {
	requireFunctions(t)
	sdk := awsclient.Lambda(endpoint("functions"), rootCreds)
	name := unique("shared-")
	createEcho(t, sdk, name)
	b := rootBrowser(t)
	arn := "arn:aws:lambda:" + region + ":000000000000:function:" + name
	form := func(page *consoletest.Response, kv ...string) url.Values {
		v := url.Values{"name": {name}, "arn": {arn}}
		if n := consoletest.Find(page.Doc, consoletest.ByName("revision")); n != nil {
			rev, _ := consoletest.Attr(n, "value")
			v.Set("revision", rev)
		}
		for i := 0; i+1 < len(kv); i += 2 {
			v.Set(kv[i], kv[i+1])
		}
		return v
	}

	page := b.Get("/lambda/function?name=" + name)
	consoletest.RequireText(t, page, "Policy", "No policy.")
	res := b.PostForm("/lambda/function/policy", form(page, "document", noPrincipal))
	requireRefused(
		t,
		res,
		"function-policy",
		"InvalidParameterValueException",
		noPrincipal,
		"Invoke",
	)

	_, err := sdk.AddPermission(t.Context(), &lambda.AddPermissionInput{
		FunctionName: aws.String(name), StatementId: aws.String("partner"),
		Action: aws.String("lambda:InvokeFunction"), Principal: aws.String("000000000000"),
	})
	requireNoErr(t, err, "add permission")
	page = b.Get("/lambda/function?name=" + name)
	consoletest.RequireText(t, page, "Statements", "partner", accountRoot)
	res = b.PostForm("/lambda/function/permission/remove", form(page, "statementId", "partner"))
	page = b.Get(res.Location())
	consoletest.RequireFlash(t, page, "ok", "Removed statement partner")
	_, err = sdk.GetPolicy(t.Context(), &lambda.GetPolicyInput{FunctionName: aws.String(name)})
	requireCode(t, err, "ResourceNotFoundException", "the policy after removing its statement")

	doc := grant("Invoke", "lambda:InvokeFunction", arn)
	res = b.PostForm("/lambda/function/policy", form(page, "document", doc))
	page = b.Get(res.Location())
	consoletest.RequireFlash(t, page, "ok", "Saved the policy of function "+name)
	requireDocument(t, page, "function-policy", doc)
	got, err := sdk.GetPolicy(t.Context(), &lambda.GetPolicyInput{FunctionName: aws.String(name)})
	requireNoErr(t, err, "get the function policy")
	if aws.ToString(got.Policy) != doc {
		t.Fatalf("stored %s, want %s", aws.ToString(got.Policy), doc)
	}

	res = b.PostForm("/lambda/function/policy/delete", form(page))
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Deleted the policy of function "+name)
	_, err = sdk.GetPolicy(t.Context(), &lambda.GetPolicyInput{FunctionName: aws.String(name)})
	requireCode(t, err, "ResourceNotFoundException", "the deleted policy")
}

func TestAnIdentitysPolicies(t *testing.T) {
	b := rootBrowser(t)
	sdk := awsclient.SESv2(endpoint("mailbox"), rootCreds)
	identity := unique("shared") + ".example.com"
	_, err := sdk.CreateEmailIdentity(t.Context(),
		&sesv2.CreateEmailIdentityInput{EmailIdentity: aws.String(identity)})
	requireNoErr(t, err, "create the identity")
	arn := "arn:aws:ses:" + region + ":000000000000:identity/" + identity
	res := b.Get("/mail/identities")
	if consoletest.Find(res.Doc, consoletest.LinkTo("/mail/identity?name="+identity)) == nil {
		t.Fatalf("the identities do not list %s: %s", identity, consoletest.Text(res.Doc))
	}

	post := func(name, doc string, isNew bool) *consoletest.Response {
		v := url.Values{"identity": {identity}, "name": {name}, "document": {doc}}
		if isNew {
			v.Set("new", "true")
		}
		return b.PostForm("/mail/identity/policy", v)
	}
	res = post("bad", noPrincipal, true)
	requireRefused(t, res, "policy-new", "BadRequestException", noPrincipal, "Verification")

	send := grant("Send", "ses:SendEmail", arn)
	raw := grant("Raw", "ses:SendRawEmail", arn)
	for name, doc := range map[string]string{"partner": send, "other": raw} {
		consoletest.RequireFlash(t, b.Get(post(name, doc, true).Location()), "ok",
			"Created policy "+name+" of "+identity)
	}
	res = post("partner", send, true)
	requireRefused(t, res, "policy-new", "AlreadyExistsException", send, "Verification")

	// Each policy is edited on its own; a refusal shows next to its form.
	res = post("partner", noPrincipal, false)
	requireRefused(t, res, "policy-partner", "BadRequestException", noPrincipal, "Verification")
	page := b.Get(post("partner", raw, false).Location())
	consoletest.RequireFlash(t, page, "ok", "Saved policy partner of "+identity)
	requireDocument(t, page, "policy-partner", raw)
	requireDocument(t, page, "policy-other", raw)

	res = b.PostForm("/mail/identity/policy/delete", url.Values{
		"identity": {identity}, "name": {"other"},
	})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Deleted policy other of "+identity)
	got, err := sdk.GetEmailIdentityPolicies(t.Context(),
		&sesv2.GetEmailIdentityPoliciesInput{EmailIdentity: aws.String(identity)})
	requireNoErr(t, err, "get the identity's policies")
	if len(got.Policies) != 1 || mustCompact(t, got.Policies["partner"]) != mustCompact(t, raw) {
		t.Fatalf("stored %v, want partner alone with %s", got.Policies, raw)
	}
}

// pageReader is an identity policy that allows reading each resource's
// page, and no policy action.
const pageReader = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":[` +
	`"s3:ListBucket","secretsmanager:DescribeSecret","secretsmanager:ListSecretVersionIds",` +
	`"sqs:GetQueueUrl","tule:Inspect","lambda:GetFunction","lambda:ListEventSourceMappings",` +
	`"ses:GetEmailIdentity"],"Resource":"*"}]}`

// deniedSection is a resource's page, the action its policy is read with,
// the form that saves the policy, the id of its section, and text of the
// rest of the page.
type deniedSection struct {
	form   url.Values
	page   string
	read   string
	save   string
	id     string
	rest   string
	saveAs string
}

// TestPolicySectionsShowTheirDenial signs in a user allowed each
// resource's page and none of the policy actions: each page renders, with
// the service's AccessDenied in its Policy section, and so does a save.
func TestPolicySectionsShowTheirDenial(t *testing.T) {
	bucket, secret, queue, identity := resources(t)
	user := unique("reader")
	key := createUserKey(t, user)
	putUserPolicy(t, user, "pages", pageReader)
	b := userBrowser(t, key)

	doc := grant("Any", "*", "*")
	sections := []deniedSection{
		{
			page: "/s3/bucket?bucket=" + bucket, read: "s3:GetBucketPolicy", rest: "Upload",
			save: "/s3/bucket/policy", saveAs: "s3:PutBucketPolicy", id: "bucket-policy",
			form: url.Values{"bucket": {bucket}, "document": {doc}},
		},
		{
			page: "/secrets/secret?id=" + secret, read: "secretsmanager:GetResourcePolicy",
			rest: "Versions", save: "/secrets/secret/policy", id: "secret-policy",
			saveAs: "secretsmanager:PutResourcePolicy",
			form:   url.Values{"id": {secret}, "document": {doc}},
		},
		{
			page: "/sqs/queue?name=" + queue, read: "sqs:GetQueueAttributes",
			rest: "Send a message", save: "/sqs/queue/policy", id: "queue-policy",
			saveAs: "sqs:SetQueueAttributes", form: url.Values{"name": {queue}, "document": {doc}},
		},
		{
			page: "/mail/identity?name=" + identity, read: "ses:GetEmailIdentityPolicies",
			rest: "Verification", save: "/mail/identity/policy", id: "policy-new",
			saveAs: "ses:CreateEmailIdentityPolicy", form: url.Values{
				"identity": {identity}, "name": {"p"}, "new": {"true"},
				// mailbox checks a document before the request is
				// evaluated, so this one names the identity.
				"document": {grant("Any", "ses:SendEmail",
					"arn:aws:ses:"+region+":000000000000:identity/"+identity)},
			},
		},
	}
	if fn.skip == "" {
		name := unique("guarded-")
		createEcho(t, awsclient.Lambda(endpoint("functions"), rootCreds), name)
		sections = append(sections, deniedSection{
			page: "/lambda/function?name=" + name, read: "lambda:GetPolicy", rest: "Invoke",
			save: "/lambda/function/policy", id: "function-policy",
			saveAs: "lambda:PutResourcePolicy", form: url.Values{
				"name":     {name},
				"arn":      {"arn:aws:lambda:" + region + ":000000000000:function:" + name},
				"document": {doc},
			},
		})
	}
	for _, s := range sections {
		res := b.Get(s.page)
		consoletest.RequireStatus(t, res, http.StatusOK)
		consoletest.RequireText(t, res, s.rest, "could not be read")
		requireDenial(t, res, s.read)

		res = b.PostForm(s.save, s.form)
		requireRefused(t, res, s.id, "AccessDenied", s.form.Get("document"), s.rest)
		requireDenial(t, res, s.saveAs)
	}
}

// requireDenial checks that the page holds the service's refusal of
// action, in any case: queues writes actions in lower case, as SQS does.
func requireDenial(t *testing.T, res *consoletest.Response, action string) {
	t.Helper()
	consoletest.RequireText(t, res, "The service answered AccessDenied")
	text := strings.ToLower(consoletest.Text(res.Doc))
	if !strings.Contains(text, strings.ToLower("is not authorized to perform: "+action)) {
		t.Fatalf("the page does not deny %s: %s", action, consoletest.Text(res.Doc))
	}
}

// resources creates a bucket, a secret, a queue and an email identity with
// the root key, and returns their names.
func resources(t *testing.T) (bucket, secret, queue, identity string) {
	t.Helper()
	bucket, secret, queue = unique("guarded-"), unique("guarded/"), unique("guarded-")
	identity = unique("guarded") + ".example.com"
	_, err := s3Client().CreateBucket(t.Context(), &s3.CreateBucketInput{Bucket: aws.String(bucket)})
	requireNoErr(t, err, "create bucket")
	value := unique("value-")
	noteSecret(value)
	_, err = awsclient.SecretsManager(endpoint("secret-store"), rootCreds).CreateSecret(t.Context(),
		&secretsmanager.CreateSecretInput{
			Name:         aws.String(secret),
			SecretString: aws.String(value),
		})
	requireNoErr(t, err, "create secret")
	_, err = awsclient.SQS(endpoint("queues"), rootCreds).CreateQueue(t.Context(),
		&sqs.CreateQueueInput{QueueName: aws.String(queue)})
	requireNoErr(t, err, "create queue")
	_, err = awsclient.SESv2(endpoint("mailbox"), rootCreds).CreateEmailIdentity(t.Context(),
		&sesv2.CreateEmailIdentityInput{EmailIdentity: aws.String(identity)})
	requireNoErr(t, err, "create the identity")
	return bucket, secret, queue, identity
}
