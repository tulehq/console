//go:build e2e

package e2e

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"golang.org/x/net/html/atom"

	"tule.dev/console/internal/awsclient"
	"tule.dev/console/internal/consoletest"
)

func TestIdentity(t *testing.T) {
	b := rootBrowser(t)
	sdk := awsclient.IAM(endpoint("identity"), rootCreds)
	user := unique("carol")

	b.Get("/iam")
	res := b.PostForm("/iam/users", url.Values{"name": {user}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Created user "+user)
	_, err := sdk.GetUser(t.Context(), &iam.GetUserInput{UserName: aws.String(user)})
	requireNoErr(t, err, "get the created user")

	// The secret is on the answer to the create, and nowhere after.
	res = b.PostForm("/iam/keys", url.Values{"user": {user}})
	consoletest.RequireStatus(t, res, http.StatusOK)
	codes := consoletest.FindAll(res.Doc, consoletest.Element(atom.Code))
	if len(codes) < 2 {
		t.Fatalf("the new key's page shows %d values", len(codes))
	}
	id, secret := consoletest.Text(codes[len(codes)-2]), consoletest.Text(codes[len(codes)-1])
	noteSecret(secret)
	keys, err := sdk.ListAccessKeys(
		t.Context(),
		&iam.ListAccessKeysInput{UserName: aws.String(user)},
	)
	requireNoErr(t, err, "list keys")
	if len(keys.AccessKeyMetadata) != 1 ||
		aws.ToString(keys.AccessKeyMetadata[0].AccessKeyId) != id {
		t.Fatalf("keys %+v, want %s", keys.AccessKeyMetadata, id)
	}
	if len(secret) != 40 {
		t.Fatalf("secret %q is not 40 characters", secret)
	}

	// The key works: it signs in to the console.
	other := browser(t)
	other.SignIn(id, secret)

	page := b.Get("/iam/user?name=" + user)
	if strings.Contains(string(page.Body), secret) {
		t.Fatal("the IAM user's page shows the secret")
	}
	consoletest.RequireText(t, page, id, "Active")
	res = b.Get("/iam")
	consoletest.RequireText(t, res, user, id)

	toggleAndDelete(t, b, sdk, user, id)
}

func requireKeyStatus(t *testing.T, sdk *iam.Client, user string, want types.StatusType) {
	t.Helper()
	keys, err := sdk.ListAccessKeys(
		t.Context(),
		&iam.ListAccessKeysInput{UserName: aws.String(user)},
	)
	requireNoErr(t, err, "list keys")
	if got := keys.AccessKeyMetadata[0].Status; got != want {
		t.Fatalf("key status %s, want %s", got, want)
	}
}

// toggleAndDelete deactivates and activates the IAM user's key, then
// deletes the key and the IAM user, through the console, checked with the
// SDK.
func toggleAndDelete(t *testing.T, b *consoletest.Browser, sdk *iam.Client, user, id string) {
	t.Helper()
	res := b.PostForm(
		"/iam/keys/status",
		url.Values{"user": {user}, "id": {id}, "status": {"Inactive"}},
	)
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Deactivated key "+id)
	requireKeyStatus(t, sdk, user, types.StatusTypeInactive)
	res = b.PostForm(
		"/iam/keys/status",
		url.Values{"user": {user}, "id": {id}, "status": {"Active"}},
	)
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Activated key "+id)
	requireKeyStatus(t, sdk, user, types.StatusTypeActive)

	// A user with a key is not deleted.
	res = b.PostForm("/iam/users/delete", url.Values{"name": {user}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "error", "was not deleted")

	res = b.PostForm("/iam/keys/delete", url.Values{"user": {user}, "id": {id}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Deleted key "+id)
	res = b.PostForm("/iam/users/delete", url.Values{"name": {user}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Deleted user "+user)
	_, err := sdk.GetUser(t.Context(), &iam.GetUserInput{UserName: aws.String(user)})
	requireCode(t, err, "NoSuchEntity", "the deleted user")
}
