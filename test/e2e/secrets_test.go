//go:build e2e

package e2e

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"

	"tule.dev/console/internal/awsclient"
	"tule.dev/console/internal/consoletest"
)

func TestSecretStore(t *testing.T) {
	b := rootBrowser(t)
	sdk := awsclient.SecretsManager(endpoint("secret-store"), rootCreds)
	name := unique("app/db-")
	first, second := unique("first-value-"), unique("second-value-")
	noteSecret(first)
	noteSecret(second)

	b.Get("/secrets")
	res := b.PostForm(
		"/secrets",
		url.Values{"name": {name}, "description": {"database password"}, "value": {first}},
	)
	page := b.Get(res.Location())
	consoletest.RequireFlash(t, page, "ok", "Created secret "+name)
	if strings.Contains(string(page.Body), first) {
		t.Fatal("the secret's page shows the value before it is revealed")
	}
	got, err := sdk.GetSecretValue(
		t.Context(),
		&secretsmanager.GetSecretValueInput{SecretId: aws.String(name)},
	)
	requireNoErr(t, err, "get the created secret")
	if aws.ToString(got.SecretString) != first {
		t.Fatalf("stored %q", aws.ToString(got.SecretString))
	}

	// Search finds it by a word of its description.
	res = b.Get("/secrets?q=" + url.QueryEscape("database "+name))
	consoletest.RequireText(t, res, name)

	res = b.PostForm("/secrets/secret/value", url.Values{"id": {name}, "value": {second}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Stored a new value")
	got, err = sdk.GetSecretValue(
		t.Context(),
		&secretsmanager.GetSecretValueInput{SecretId: aws.String(name)},
	)
	requireNoErr(t, err, "get the new value")
	if aws.ToString(got.SecretString) != second {
		t.Fatalf("current value %q", aws.ToString(got.SecretString))
	}

	// The versions show their labels; each reveals its own value.
	page = b.Get("/secrets/secret?id=" + url.QueryEscape(name))
	consoletest.RequireText(t, page, "AWSCURRENT", "AWSPREVIOUS")
	res = b.HTMXPost("/secrets/secret/reveal", url.Values{"id": {name}})
	consoletest.RequireText(t, res, second)
	prev, err := sdk.GetSecretValue(t.Context(), &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(name), VersionStage: aws.String("AWSPREVIOUS"),
	})
	requireNoErr(t, err, "get the previous value")
	res = b.PostForm(
		"/secrets/secret/reveal",
		url.Values{"id": {name}, "versionId": {aws.ToString(prev.VersionId)}},
	)
	consoletest.RequireText(t, res, first)

	deleteAndRestore(t, b, sdk, name)
}

// deleteAndRestore deletes name with a recovery window, restores it, and
// deletes it for good, each through the console, checked with the SDK.
func deleteAndRestore(
	t *testing.T,
	b *consoletest.Browser,
	sdk *secretsmanager.Client,
	name string,
) {
	t.Helper()
	res := b.PostForm("/secrets/secret/delete", url.Values{"id": {name}, "days": {"7"}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "scheduled for deletion")
	d, err := sdk.DescribeSecret(
		t.Context(),
		&secretsmanager.DescribeSecretInput{SecretId: aws.String(name)},
	)
	requireNoErr(t, err, "describe the deleted secret")
	if d.DeletedDate == nil {
		t.Fatal("the secret is not scheduled for deletion")
	}
	res = b.PostForm("/secrets/secret/restore", url.Values{"id": {name}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Restored secret")
	d, err = sdk.DescribeSecret(
		t.Context(),
		&secretsmanager.DescribeSecretInput{SecretId: aws.String(name)},
	)
	requireNoErr(t, err, "describe the restored secret")
	if d.DeletedDate != nil {
		t.Fatal("the secret is still scheduled for deletion")
	}
	res = b.PostForm("/secrets/secret/delete", url.Values{"id": {name}, "force": {"on"}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "without recovery")
	_, err = sdk.DescribeSecret(
		t.Context(),
		&secretsmanager.DescribeSecretInput{SecretId: aws.String(name)},
	)
	requireCode(t, err, "ResourceNotFoundException", "the force-deleted secret")
	consoletest.RequireStatus(
		t,
		b.Get("/secrets/secret?id="+url.QueryEscape(name)),
		http.StatusBadRequest,
	)
}
