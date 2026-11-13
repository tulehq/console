//go:build e2e

package e2e

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"tule.dev/console/internal/awsclient"
	"tule.dev/console/internal/consoletest"
)

// listBucketsOnly is an identity policy that allows s3:ListAllMyBuckets
// and nothing else.
const listBucketsOnly = `{"Version":"2012-10-17","Statement":[` +
	`{"Effect":"Allow","Action":"s3:ListAllMyBuckets","Resource":"*"}]}`

// deniedEverywhere is each section's first page, with the action its
// service denies a principal no policy allows anything.
func deniedEverywhere() map[string]string {
	pages := map[string]string{
		"/s3":       "s3:ListAllMyBuckets",
		"/secrets":  "secretsmanager:ListSecrets",
		"/accounts": "organizations:DescribeOrganization",
		"/iam":      "iam:ListUsers",
		"/mail":     "tule:Inspect",
		"/sqs":      "tule:Inspect",
	}
	if fn.skip == "" {
		pages["/lambda"] = "lambda:ListFunctions"
		pages["/lambda/invocations"] = "tule:Inspect"
	}
	return pages
}

// requireDenied checks that res is a page with the service's AccessDenied
// for action: a 400 or 403, as each service answers it, never a fault of
// the console's or a broken page.
func requireDenied(t *testing.T, res *consoletest.Response, action string) {
	t.Helper()
	if res.Status != http.StatusForbidden && res.Status != http.StatusBadRequest {
		t.Fatalf("denied %s: status %d, want 400 or 403: %s",
			action, res.Status, consoletest.Text(res.Doc))
	}
	consoletest.RequireText(t, res, "The service answered AccessDenied")
	// queues writes the action in lower case, as SQS does.
	text := strings.ToLower(consoletest.Text(res.Doc))
	if !strings.Contains(text, strings.ToLower("is not authorized to perform: "+action)) {
		t.Fatalf("the page does not deny %s: %s", action, consoletest.Text(res.Doc))
	}
}

// putUserPolicy gives the IAM user an inline policy through the console's own
// form, signed in with the root key.
func putUserPolicy(t *testing.T, user, name, doc string) {
	t.Helper()
	b := rootBrowser(t)
	b.Get("/iam/user/policy?user=" + url.QueryEscape(user))
	res := b.PostForm("/iam/user/policy", url.Values{
		"user": {user}, "name": {name}, "new": {"true"}, "document": {doc},
	})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Saved inline policy "+name)
}

func userBrowser(t *testing.T, key aws.Credentials) *consoletest.Browser {
	t.Helper()
	b := browser(t)
	b.SignIn(key.AccessKeyID, key.SecretAccessKey)
	return b
}

func TestAPolicyAllowsOnlyWhatItSays(t *testing.T) {
	bucket := unique("listed-")
	_, err := s3Client().CreateBucket(t.Context(), &s3.CreateBucketInput{Bucket: aws.String(bucket)})
	requireNoErr(t, err, "create bucket")

	user := unique("lister")
	key := createUserKey(t, user)
	putUserPolicy(t, user, "list-buckets", listBucketsOnly)
	b := userBrowser(t, key)

	res := b.Get("/s3")
	consoletest.RequireStatus(t, res, http.StatusOK)
	consoletest.RequireText(t, res, bucket)

	// Reading the bucket is another action, which the policy does not allow.
	requireDenied(t, b.Get("/s3/bucket?bucket="+bucket), "s3:ListBucket")

	requireDenied(t, b.Get("/secrets"), "secretsmanager:ListSecrets")
	// A search, as htmx sends it, gets the refusal alone, for htmx to swap
	// where the results go.
	res = b.HTMX("/secrets?q=db")
	requireDenied(t, res, "secretsmanager:ListSecrets")
	if strings.Contains(string(res.Body), "<html") {
		t.Fatal("the search's refusal answered the whole page")
	}

	// An action comes back to its page with the service's message.
	name := unique("refused-")
	res = b.PostForm("/s3/buckets", url.Values{"bucket": {name}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "error",
		"is not authorized to perform: s3:CreateBucket")

	for path, action := range deniedEverywhere() {
		if path != "/s3" {
			requireDenied(t, b.Get(path), action)
		}
	}
}

// TestInspectionNeedsTuleInspect gives a user every action of the AWS APIs
// of mailbox, queues and functions, and then tule:Inspect, which their
// inspection pages need besides.
func TestInspectionNeedsTuleInspect(t *testing.T) {
	user := unique("inspector")
	key := createUserKey(t, user)
	putUserPolicy(t, user, "apis", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",`+
		`"Action":["ses:*","sqs:*","lambda:*"],"Resource":"*"}]}`)
	b := userBrowser(t, key)

	inspection := []string{"/mail", "/mail/failures", "/sqs"}
	if fn.skip == "" {
		consoletest.RequireStatus(t, b.Get("/lambda"), http.StatusOK)
		inspection = append(inspection, "/lambda/invocations")
	}
	for _, path := range inspection {
		requireDenied(t, b.Get(path), "tule:Inspect")
	}

	putUserPolicy(t, user, "inspect", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",`+
		`"Action":"tule:Inspect","Resource":"*"}]}`)
	for _, path := range inspection {
		consoletest.RequireStatus(t, b.Get(path), http.StatusOK)
	}
}

func TestTheRootKeySeesEverything(t *testing.T) {
	b := rootBrowser(t)
	pages := []string{
		"/s3", "/secrets", "/accounts", "/iam", "/iam/roles", "/iam/policies",
		"/iam/policy?arn=" + url.QueryEscape("arn:aws:iam::aws:policy/AdministratorAccess"),
		"/mail", "/mail/failures", "/sqs",
	}
	if fn.skip == "" {
		pages = append(pages, "/lambda", "/lambda/invocations", "/lambda/mappings")
	}
	for _, path := range pages {
		res := b.Get(path)
		consoletest.RequireStatus(t, res, http.StatusOK)
		if strings.Contains(consoletest.Text(res.Doc), "AccessDenied") {
			t.Fatalf("%s denies the root key: %s", path, consoletest.Text(res.Doc))
		}
	}
}

// TestARoleWithAManagedPolicy creates a managed policy and a role through
// the console, attaches the one to the other, and signs in with a session
// of the role, which may do what the policy allows and nothing else.
func TestARoleWithAManagedPolicy(t *testing.T) {
	b := rootBrowser(t)
	sdk := awsclient.IAM(endpoint("identity"), rootCreds)
	policyName, roleName := unique("lister-"), unique("viewer-")

	// identity's MalformedPolicyDocument is shown next to the form.
	b.Get("/iam/policies/new")
	res := b.PostForm("/iam/policies", url.Values{
		"name": {policyName}, "document": {`{"Statement":[{"Effect":"Allow"}]}`},
	})
	consoletest.RequireStatus(t, res, http.StatusBadRequest)
	consoletest.RequireText(t, res, "MalformedPolicyDocument")
	if consoletest.Find(res.Doc, consoletest.ByID("form-error")) == nil {
		t.Fatal("the refusal is not next to the form")
	}

	res = b.PostForm(
		"/iam/policies",
		url.Values{"name": {policyName}, "document": {listBucketsOnly}},
	)
	consoletest.RequireStatus(t, res, http.StatusSeeOther)
	page := b.Get(res.Location())
	consoletest.RequireFlash(t, page, "ok", "Created policy "+policyName)
	consoletest.RequireText(t, page, `"Action": "s3:ListAllMyBuckets"`)
	policyARN := "arn:aws:iam::000000000000:policy/" + policyName

	b.Get("/iam/roles/new")
	res = b.PostForm("/iam/roles", url.Values{
		"name": {roleName}, "trust": {`{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
			`"Action":"sts:AssumeRole"}]}`},
	})
	consoletest.RequireStatus(t, res, http.StatusBadRequest)
	consoletest.RequireText(t, res, "MalformedPolicyDocument")

	res = b.PostForm("/iam/roles", url.Values{
		"name": {roleName}, "trust": {`{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
			`"Principal":{"AWS":"arn:aws:iam::000000000000:root"},"Action":"sts:AssumeRole"}]}`},
	})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Created role "+roleName)
	res = b.PostForm("/iam/role/attach", url.Values{"role": {roleName}, "arn": {policyARN}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Attached "+policyARN)

	requireAttached(t, sdk, roleName, policyARN)
	page = b.Get("/iam/role?name=" + roleName)
	consoletest.RequireText(
		t,
		page,
		policyName,
		`"sts:AssumeRole"`,
		"arn:aws:iam::000000000000:root",
	)

	// A session of the role lists buckets, and is denied secrets.
	session := roleBrowser(t, roleName)
	consoletest.RequireStatus(t, session.Get("/s3"), http.StatusOK)
	requireDenied(t, session.Get("/secrets"), "secretsmanager:ListSecrets")

	deletePolicyAndRole(t, b, sdk, policyARN, roleName)
}

// requireAttached checks with the SDK that the role has the one policy
// attached.
func requireAttached(t *testing.T, sdk *iam.Client, roleName, policyARN string) {
	t.Helper()
	attached, err := sdk.ListAttachedRolePolicies(t.Context(),
		&iam.ListAttachedRolePoliciesInput{RoleName: aws.String(roleName)})
	requireNoErr(t, err, "list the role's policies")
	if len(attached.AttachedPolicies) != 1 ||
		aws.ToString(attached.AttachedPolicies[0].PolicyArn) != policyARN {
		t.Fatalf("attached %+v, want %s", attached.AttachedPolicies, policyARN)
	}
}

// roleBrowser returns a browser signed in with a session of the role,
// assumed with the root key.
func roleBrowser(t *testing.T, roleName string) *consoletest.Browser {
	t.Helper()
	out, err := awsclient.STS(endpoint("identity"), rootCreds).AssumeRole(t.Context(),
		&sts.AssumeRoleInput{
			RoleArn:         aws.String("arn:aws:iam::000000000000:role/" + roleName),
			RoleSessionName: aws.String("console-e2e"),
		})
	requireNoErr(t, err, "assume the role")
	c := out.Credentials
	noteSecret(aws.ToString(c.SecretAccessKey))
	noteSecret(aws.ToString(c.SessionToken))
	session := browser(t)
	session.Get("/signin")
	res := session.PostForm("/signin", url.Values{
		"accessKeyId":     {aws.ToString(c.AccessKeyId)},
		"secretAccessKey": {aws.ToString(c.SecretAccessKey)},
		"sessionToken":    {aws.ToString(c.SessionToken)},
	})
	consoletest.RequireStatus(t, res, http.StatusSeeOther)
	return session
}

// deletePolicyAndRole detaches the policy and deletes it and the role
// through the console, checked with the SDK. The policy is not deleted
// while it is attached.
func deletePolicyAndRole(
	t *testing.T, b *consoletest.Browser, sdk *iam.Client, policyARN, roleName string,
) {
	t.Helper()
	res := b.PostForm("/iam/policies/delete", url.Values{"arn": {policyARN}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "error", "was not deleted")
	res = b.PostForm("/iam/role/detach", url.Values{"role": {roleName}, "arn": {policyARN}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Detached "+policyARN)
	res = b.PostForm("/iam/roles/delete", url.Values{"name": {roleName}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Deleted role "+roleName)
	res = b.PostForm("/iam/policies/delete", url.Values{"arn": {policyARN}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Deleted policy "+policyARN)
	_, err := sdk.GetRole(t.Context(), &iam.GetRoleInput{RoleName: aws.String(roleName)})
	requireCode(t, err, "NoSuchEntity", "the deleted role")
	_, err = sdk.GetPolicy(t.Context(), &iam.GetPolicyInput{PolicyArn: aws.String(policyARN)})
	requireCode(t, err, "NoSuchEntity", "the deleted policy")
}

// TestAUsersPolicies puts, reads and deletes a user's inline policy and
// attaches and detaches AdministratorAccess, through the console.
func TestAUsersPolicies(t *testing.T) {
	b := rootBrowser(t)
	sdk := awsclient.IAM(endpoint("identity"), rootCreds)
	user := unique("auditor")
	_, err := sdk.CreateUser(t.Context(), &iam.CreateUserInput{UserName: aws.String(user)})
	requireNoErr(t, err, "create user")

	b.Get("/iam/user/policy?user=" + user)
	res := b.PostForm("/iam/user/policy", url.Values{
		"user": {user}, "name": {"bad"}, "new": {"true"}, "document": {`{"Version":"2012-10-17"}`},
	})
	consoletest.RequireStatus(t, res, http.StatusBadRequest)
	consoletest.RequireText(t, res, "MalformedPolicyDocument")
	putUserPolicy(t, user, "list", listBucketsOnly)

	got, err := sdk.GetUserPolicy(t.Context(),
		&iam.GetUserPolicyInput{UserName: aws.String(user), PolicyName: aws.String("list")})
	requireNoErr(t, err, "get the inline policy")
	if doc, _ := url.QueryUnescape(aws.ToString(got.PolicyDocument)); doc != listBucketsOnly {
		t.Fatalf("stored document %q", doc)
	}
	page := b.Get("/iam/user/policy?user=" + user + "&name=list")
	consoletest.RequireText(t, page, `"Action": "s3:ListAllMyBuckets"`)

	admin := "arn:aws:iam::aws:policy/AdministratorAccess"
	b.Get("/iam/user?name=" + user)
	res = b.PostForm("/iam/user/attach", url.Values{"user": {user}, "arn": {admin}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Attached "+admin)
	page = b.Get("/iam/user?name=" + user)
	consoletest.RequireText(t, page, "list", "AdministratorAccess", "Detach")

	res = b.PostForm("/iam/user/detach", url.Values{"user": {user}, "arn": {admin}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Detached "+admin)
	res = b.PostForm("/iam/user/policy/delete", url.Values{"user": {user}, "name": {"list"}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Deleted inline policy list")
	res = b.PostForm("/iam/users/delete", url.Values{"name": {user}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Deleted user "+user)
}
