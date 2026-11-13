//go:build e2e

package e2e

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"tule.dev/console/internal/awsclient"
	"tule.dev/console/internal/consoletest"
)

func TestSignInWithTheRootKey(t *testing.T) {
	b := rootBrowser(t)
	res := b.Get("/")
	consoletest.RequireStatus(t, res, http.StatusOK)
	consoletest.RequireText(t, res, "arn:aws:iam::000000000000:root",
		"Object store", "Secret store", "Accounts", "Identity", "Mailbox", "Queues")
	if strings.Contains(consoletest.Text(res.Doc), "unreachable") ||
		strings.Contains(consoletest.Text(res.Doc), "not ready") {
		t.Fatalf("a service is not ready: %s", consoletest.Text(res.Doc))
	}
	if strings.Contains(string(res.Body), rootSecret) {
		t.Fatal("a page carries the secret")
	}
}

// createUserKey creates an IAM user and a key for it through identity's
// own SDK client.
func createUserKey(t *testing.T, user string) aws.Credentials {
	t.Helper()
	ic := awsclient.IAM(endpoint("identity"), rootCreds)
	_, err := ic.CreateUser(t.Context(), &iam.CreateUserInput{UserName: aws.String(user)})
	requireNoErr(t, err, "create user "+user)
	out, err := ic.CreateAccessKey(
		t.Context(),
		&iam.CreateAccessKeyInput{UserName: aws.String(user)},
	)
	requireNoErr(t, err, "create a key for "+user)
	key := aws.Credentials{
		AccessKeyID:     aws.ToString(out.AccessKey.AccessKeyId),
		SecretAccessKey: aws.ToString(out.AccessKey.SecretAccessKey),
	}
	noteSecret(key.SecretAccessKey)
	return key
}

func TestSignInWithAnIdentityKey(t *testing.T) {
	user := unique("dev")
	key := createUserKey(t, user)

	b := browser(t)
	b.SignIn(key.AccessKeyID, key.SecretAccessKey)
	res := b.Get("/")
	consoletest.RequireText(t, res, "arn:aws:iam::000000000000:user/"+user)

	// Every section takes the identity-issued key, as each service does.
	for _, path := range []string{"/s3", "/secrets", "/mail", "/sqs"} {
		consoletest.RequireStatus(t, b.Get(path), http.StatusOK)
	}
	// Identity holds a user to its permissions, and the page says so.
	res = b.Get("/iam")
	consoletest.RequireStatus(t, res, http.StatusForbidden)
	consoletest.RequireText(t, res, "AccessDenied", "iam:ListUsers")

	// A key identity deactivates is refused from then on.
	_, err := awsclient.IAM(endpoint("identity"), rootCreds).
		UpdateAccessKey(t.Context(), &iam.UpdateAccessKeyInput{
			UserName: aws.String(
				user,
			),
			AccessKeyId: aws.String(key.AccessKeyID),
			Status:      "Inactive",
		})
	requireNoErr(t, err, "deactivate the key")
	res = b.Get("/s3")
	consoletest.RequireStatus(t, res, http.StatusForbidden)
	res = browser(t).TrySignIn(key.AccessKeyID, key.SecretAccessKey, "")
	consoletest.RequireStatus(t, res, http.StatusUnauthorized)
}

func TestWrongKeyRefused(t *testing.T) {
	b := browser(t)
	res := b.TrySignIn(rootKeyID, "not-the-secret", "")
	consoletest.RequireStatus(t, res, http.StatusUnauthorized)
	consoletest.RequireText(t, res, "The key was refused")
	res = b.TrySignIn("AKIAUNKNOWNKEY000000", rootSecret, "")
	consoletest.RequireStatus(t, res, http.StatusUnauthorized)
	consoletest.RequireStatus(t, b.Get("/s3"), http.StatusSeeOther)
}

func TestSignedOutRedirects(t *testing.T) {
	b := browser(t)
	for _, path := range []string{"/", "/s3", "/secrets", "/accounts", "/iam", "/mail", "/sqs"} {
		res := b.Get(path)
		consoletest.RequireStatus(t, res, http.StatusSeeOther)
		if !strings.HasPrefix(res.Location(), "/signin") {
			t.Fatalf("%s redirects to %q", path, res.Location())
		}
	}
}

func TestPostsWithoutTheTokenRefused(t *testing.T) {
	b := rootBrowser(t)
	name := unique("csrf")
	res := b.PostForm("/s3/buckets", url.Values{"bucket": {name}, "_csrf": {""}})
	consoletest.RequireStatus(t, res, http.StatusForbidden)
	req := b.FormRequest("/s3/buckets", url.Values{"bucket": {name}})
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	consoletest.RequireStatus(t, b.Do(req), http.StatusForbidden)

	out, err := awsclient.S3(endpoint("object-store"), rootCreds).ListBuckets(t.Context(), nil)
	requireNoErr(t, err, "list buckets")
	for _, bk := range out.Buckets {
		if aws.ToString(bk.Name) == name {
			t.Fatal("a post without its token created a bucket")
		}
	}
}

func TestSignOut(t *testing.T) {
	b := rootBrowser(t)
	consoletest.RequireStatus(t, b.PostForm("/signout", nil), http.StatusSeeOther)
	consoletest.RequireStatus(t, b.Get("/"), http.StatusSeeOther)
}

// TestSignInWithARoleSession signs in with a session of a member account's
// OrganizationAccountAccessRole, its key and token, as identity issues it.
func TestSignInWithARoleSession(t *testing.T) {
	orgs := awsclient.Organizations(endpoint("accounts"), rootCreds)
	ensureOrganization(t, orgs)
	name := unique("member")
	out, err := orgs.CreateAccount(t.Context(), &organizations.CreateAccountInput{
		AccountName: aws.String(name), Email: aws.String(name + "@example.com"),
	})
	requireNoErr(t, err, "create the member account")
	account := aws.ToString(out.CreateAccountStatus.AccountId)

	roleARN := "arn:aws:iam::" + account + ":role/OrganizationAccountAccessRole"
	stsClient := awsclient.STS(endpoint("identity"), rootCreds)
	role, err := stsClient.AssumeRole(t.Context(), &sts.AssumeRoleInput{
		RoleArn:         aws.String(roleARN),
		RoleSessionName: aws.String("console-e2e"),
	})
	requireNoErr(t, err, "assume the role")
	c := role.Credentials
	noteSecret(aws.ToString(c.SecretAccessKey))
	noteSecret(aws.ToString(c.SessionToken))

	b := browser(t)
	b.Get("/signin")
	res := b.PostForm("/signin", url.Values{
		"accessKeyId":     {aws.ToString(c.AccessKeyId)},
		"secretAccessKey": {aws.ToString(c.SecretAccessKey)},
		"sessionToken":    {aws.ToString(c.SessionToken)},
	})
	consoletest.RequireStatus(t, res, http.StatusSeeOther)
	res = b.Get("/")
	consoletest.RequireText(t, res,
		"arn:aws:sts::"+account+":assumed-role/OrganizationAccountAccessRole/console-e2e")
	if strings.Contains(string(res.Body), aws.ToString(c.SessionToken)) {
		t.Fatal("a page carries the session token")
	}
	// The session is an admin principal of its own account in identity.
	consoletest.RequireStatus(t, b.Get("/iam"), http.StatusOK)
	consoletest.RequireStatus(t, b.Get("/s3"), http.StatusOK)

	// Without its token, the session's key is refused.
	res = browser(t).TrySignIn(aws.ToString(c.AccessKeyId), aws.ToString(c.SecretAccessKey), "")
	consoletest.RequireStatus(t, res, http.StatusUnauthorized)
}
