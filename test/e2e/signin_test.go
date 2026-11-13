//go:build e2e

package e2e

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/gasmod/gas/config"

	"tule.dev/console/internal/app"
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

	// A user with no policies signs in: GetCallerIdentity needs none.
	b := browser(t)
	b.SignIn(key.AccessKeyID, key.SecretAccessKey)
	res := b.Get("/")
	consoletest.RequireText(t, res, "arn:aws:iam::000000000000:user/"+user)

	// Every service takes the identity-issued key and denies it everything,
	// and each section shows that service's AccessDenied.
	for path, action := range deniedEverywhere() {
		requireDenied(t, b.Get(path), action)
	}

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
	// The session is an admin principal of its own account in identity,
	// and a principal of another account to object-store, which lists it
	// its own account's buckets, none, and refuses it a bucket of the
	// services' account that no bucket policy shares with it.
	consoletest.RequireStatus(t, b.Get("/iam"), http.StatusOK)
	bucket := unique("unshared-")
	_, err = s3Client().CreateBucket(t.Context(), &s3.CreateBucketInput{Bucket: aws.String(bucket)})
	requireNoErr(t, err, "create bucket")
	res = b.Get("/s3")
	consoletest.RequireStatus(t, res, http.StatusOK)
	if strings.Contains(consoletest.Text(res.Doc), bucket) {
		t.Fatal("another account's session lists the services' account's buckets")
	}
	res = b.Get("/s3/bucket?bucket=" + bucket)
	consoletest.RequireStatus(t, res, http.StatusForbidden)
	consoletest.RequireText(t, res, "AccessDenied", "no resource-based policy allows")

	// Without its token, the session's key is refused.
	res = browser(t).TrySignIn(aws.ToString(c.AccessKeyId), aws.ToString(c.SecretAccessKey), "")
	consoletest.RequireStatus(t, res, http.StatusUnauthorized)
}

// objectStoreConsole runs a second console pointed at object-store alone,
// without identity, so a key is checked with ListBuckets. It does not log,
// so the suite's log check stays the first console's.
func objectStoreConsole(t *testing.T) *consoletest.Browser {
	t.Helper()
	t.Setenv("TULE_GasEnv", "testing")
	for _, name := range []string{
		"Identity", "Accounts", "SecretStore", "Mailbox", "Queues", "Functions",
	} {
		t.Setenv("TULE_Console_"+name+"Endpoint", "")
	}
	t.Setenv("TULE_Console_ObjectStoreEndpoint", stack.urls["object-store"])
	cfg, err := app.LoadConfigFrom(
		config.NewEnvProvider(config.WithEnvSeparator("_"), config.WithEnvPrefix("TULE_")),
	)
	requireNoErr(t, err, "load the second console's config")
	a, err := app.New(cfg)
	requireNoErr(t, err, "build the second console")
	requireNoErr(t, a.Start(context.Background()), "start the second console")
	l, err := net.Listen("tcp", "127.0.0.1:0")
	requireNoErr(t, err, "listen")
	served := make(chan error, 1)
	go func() { served <- a.Server().Serve(l) }()
	t.Cleanup(func() {
		if err := a.Stop(context.Background()); err != nil {
			t.Errorf("stop the second console: %v", err)
		}
		if err := <-served; err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("serve the second console: %v", err)
		}
	})
	return (&consoletest.Server{URL: "http://" + l.Addr().String()}).Browser(t)
}

// TestSignInWithoutIdentity signs in to a console that checks keys with
// object-store's ListBuckets. object-store still verifies the keys identity
// issued, through identity, and evaluates their policies.
func TestSignInWithoutIdentity(t *testing.T) {
	b := objectStoreConsole(t)

	// A wrong secret fails object-store's signature check, and is refused.
	res := b.TrySignIn(rootKeyID, "not-the-secret", "")
	consoletest.RequireStatus(t, res, http.StatusUnauthorized)
	consoletest.RequireText(t, res, "The key was refused")

	// A key with no policies is denied ListBuckets by policy, which only
	// comes past the signature check: it signs in, and is shown the denial.
	user := unique("solo")
	key := createUserKey(t, user)
	b.SignIn(key.AccessKeyID, key.SecretAccessKey)
	res = b.Get("/")
	consoletest.RequireText(t, res, "arn:aws:iam::000000000000:user/"+user)
	if strings.Contains(consoletest.Text(res.Doc), "Identity") {
		t.Fatal("the second console has an identity section")
	}
	requireDenied(t, b.Get("/s3"), "s3:ListAllMyBuckets")
}
