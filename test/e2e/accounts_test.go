//go:build e2e

package e2e

import (
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"

	"tule.dev/console/internal/awsclient"
	"tule.dev/console/internal/consoletest"
)

func TestAccounts(t *testing.T) {
	b := rootBrowser(t)
	sdk := awsclient.Organizations(endpoint("accounts"), rootCreds)

	// The organization exists once, whichever test made it first: made
	// here through the console when there is none.
	_, err := sdk.DescribeOrganization(t.Context(), &organizations.DescribeOrganizationInput{})
	var notInUse *types.AWSOrganizationsNotInUseException
	if errors.As(err, &notInUse) {
		res := b.Get("/accounts")
		consoletest.RequireText(t, res, "There is no organization yet")
		res = b.PostForm("/accounts/organization", nil)
		consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Created the organization.")
	}
	org, err := sdk.DescribeOrganization(t.Context(), &organizations.DescribeOrganizationInput{})
	requireNoErr(t, err, "describe the organization")

	roots, err := sdk.ListRoots(t.Context(), &organizations.ListRootsInput{})
	requireNoErr(t, err, "list roots")
	root := aws.ToString(roots.Roots[0].Id)

	res := b.Get("/accounts")
	consoletest.RequireStatus(t, res, http.StatusOK)
	consoletest.RequireText(t, res, aws.ToString(org.Organization.Id), root, "Management")

	ou := unique("Workloads")
	res = b.PostForm("/accounts/ous", url.Values{"parentId": {root}, "name": {ou}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Created unit "+ou)
	ous, err := sdk.ListOrganizationalUnitsForParent(t.Context(),
		&organizations.ListOrganizationalUnitsForParentInput{ParentId: aws.String(root)})
	requireNoErr(t, err, "list units")
	found := false
	for _, u := range ous.OrganizationalUnits {
		found = found || aws.ToString(u.Name) == ou
	}
	if !found {
		t.Fatalf("no unit %s under the root", ou)
	}

	createAccount(t, b, sdk, root, ou)
}

// createAccount creates an account in the root through the console, and
// checks it with the SDK and on its page.
func createAccount(
	t *testing.T,
	b *consoletest.Browser,
	sdk *organizations.Client,
	root, ou string,
) {
	t.Helper()
	name := unique("shop")
	email := name + "@example.com"
	res := b.PostForm("/accounts/accounts", url.Values{"name": {name}, "email": {email}})
	page := b.Get(res.Location())
	consoletest.RequireFlash(t, page, "ok", "Created account "+name)
	consoletest.RequireText(t, page, email, "ACTIVE")

	accts, err := sdk.ListAccountsForParent(
		t.Context(),
		&organizations.ListAccountsForParentInput{ParentId: aws.String(root)},
	)
	requireNoErr(t, err, "list accounts")
	var id string
	for _, a := range accts.Accounts {
		if aws.ToString(a.Email) == email {
			id = aws.ToString(a.Id)
		}
	}
	if id == "" {
		t.Fatalf("no account %s under the root", email)
	}
	_, err = sdk.TagResource(t.Context(), &organizations.TagResourceInput{
		ResourceId: aws.String(
			id,
		),
		Tags: []types.Tag{{Key: aws.String("team"), Value: aws.String("growth")}},
	})
	requireNoErr(t, err, "tag the account")
	res = b.Get("/accounts/account?id=" + id)
	consoletest.RequireText(t, res, name, email, "team", "growth", root)

	res = b.Get("/accounts")
	consoletest.RequireText(t, res, ou, name)

	// The same email again fails as Organizations reports it.
	res = b.PostForm("/accounts/accounts", url.Values{"name": {"again"}, "email": {email}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "error", "EMAIL_ALREADY_EXISTS")
}

// ensureOrganization creates the organization through its SDK when there
// is none, for tests that need one whatever ran first.
func ensureOrganization(t *testing.T, sdk *organizations.Client) {
	t.Helper()
	_, err := sdk.DescribeOrganization(t.Context(), &organizations.DescribeOrganizationInput{})
	var notInUse *types.AWSOrganizationsNotInUseException
	if errors.As(err, &notInUse) {
		_, err = sdk.CreateOrganization(t.Context(), &organizations.CreateOrganizationInput{})
	}
	requireNoErr(t, err, "the organization")
}
