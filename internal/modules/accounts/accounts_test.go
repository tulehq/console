package accounts_test

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"

	"tule.dev/console/internal/app"
	"tule.dev/console/internal/consoletest"
	"tule.dev/console/internal/modules/accounts"
)

type node struct {
	id, name, parent, kind, email string
	tags                          []types.Tag
}

// fakeOrg is an organization in memory: a root, OUs and accounts.
type fakeOrg struct {
	nodes  []*node
	exists bool
	mu     sync.Mutex
}

func newFake() *fakeOrg {
	return &fakeOrg{exists: true, nodes: []*node{
		{id: "r-abcd", name: "Root", kind: "root"},
		{
			id:     "000000000000",
			name:   "Management",
			parent: "r-abcd",
			kind:   "account",
			email:  "management@example.com",
		},
	}}
}

func (f *fakeOrg) get(id string) *node {
	for _, n := range f.nodes {
		if n.id == id {
			return n
		}
	}
	return nil
}

func notInUse() error {
	return &types.AWSOrganizationsNotInUseException{
		Message: aws.String("Your account is not a member of an organization."),
	}
}

func (f *fakeOrg) DescribeOrganization(
	context.Context, *organizations.DescribeOrganizationInput, ...func(*organizations.Options),
) (*organizations.DescribeOrganizationOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.exists {
		return nil, notInUse()
	}
	return &organizations.DescribeOrganizationOutput{Organization: &types.Organization{
		Id: aws.String(
			"o-abcdefghij",
		),
		Arn: aws.String(
			"arn:aws:organizations::000000000000:organization/o-abcdefghij",
		),
		FeatureSet:      types.OrganizationFeatureSetAll,
		MasterAccountId: aws.String("000000000000"),
	}}, nil
}

func (f *fakeOrg) CreateOrganization(
	context.Context, *organizations.CreateOrganizationInput, ...func(*organizations.Options),
) (*organizations.CreateOrganizationOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.exists = true
	return &organizations.CreateOrganizationOutput{}, nil
}

func (f *fakeOrg) ListRoots(
	context.Context, *organizations.ListRootsInput, ...func(*organizations.Options),
) (*organizations.ListRootsOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := &organizations.ListRootsOutput{}
	for _, n := range f.nodes {
		if n.kind == "root" {
			out.Roots = append(
				out.Roots,
				types.Root{Id: aws.String(n.id), Name: aws.String(n.name)},
			)
		}
	}
	return out, nil
}

func (f *fakeOrg) ListOrganizationalUnitsForParent(
	_ context.Context,
	in *organizations.ListOrganizationalUnitsForParentInput,
	_ ...func(*organizations.Options),
) (*organizations.ListOrganizationalUnitsForParentOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := &organizations.ListOrganizationalUnitsForParentOutput{}
	for _, n := range f.nodes {
		if n.kind == "ou" && n.parent == *in.ParentId {
			out.OrganizationalUnits = append(out.OrganizationalUnits,
				types.OrganizationalUnit{Id: aws.String(n.id), Name: aws.String(n.name)})
		}
	}
	return out, nil
}

func (f *fakeOrg) ListAccountsForParent(
	_ context.Context,
	in *organizations.ListAccountsForParentInput,
	_ ...func(*organizations.Options),
) (*organizations.ListAccountsForParentOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := &organizations.ListAccountsForParentOutput{}
	for _, n := range f.nodes {
		if n.kind == "account" && n.parent == *in.ParentId {
			out.Accounts = append(out.Accounts, types.Account{
				Id: aws.String(
					n.id,
				),
				Name:  aws.String(n.name),
				Email: aws.String(n.email),
				State: types.AccountStateActive,
			})
		}
	}
	return out, nil
}

func (f *fakeOrg) DescribeAccount(
	_ context.Context, in *organizations.DescribeAccountInput, _ ...func(*organizations.Options),
) (*organizations.DescribeAccountOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := f.get(*in.AccountId)
	if n == nil || n.kind != "account" {
		return nil, &types.AccountNotFoundException{
			Message: aws.String("You specified an account that doesn't exist."),
		}
	}
	return &organizations.DescribeAccountOutput{Account: &types.Account{
		Id: aws.String(
			n.id,
		),
		Name:         aws.String(n.name),
		Email:        aws.String(n.email),
		State:        types.AccountStateActive,
		JoinedMethod: types.AccountJoinedMethodCreated,
	}}, nil
}

func (f *fakeOrg) ListParents(
	_ context.Context, in *organizations.ListParentsInput, _ ...func(*organizations.Options),
) (*organizations.ListParentsOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := f.get(*in.ChildId)
	return &organizations.ListParentsOutput{
		Parents: []types.Parent{{Id: aws.String(n.parent), Type: types.ParentTypeRoot}},
	}, nil
}

func (f *fakeOrg) ListTagsForResource(
	_ context.Context,
	in *organizations.ListTagsForResourceInput,
	_ ...func(*organizations.Options),
) (*organizations.ListTagsForResourceOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return &organizations.ListTagsForResourceOutput{Tags: f.get(*in.ResourceId).tags}, nil
}

func (f *fakeOrg) CreateAccount(
	_ context.Context, in *organizations.CreateAccountInput, _ ...func(*organizations.Options),
) (*organizations.CreateAccountOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, n := range f.nodes {
		if n.email == *in.Email {
			return &organizations.CreateAccountOutput{
				CreateAccountStatus: &types.CreateAccountStatus{
					State:         types.CreateAccountStateFailed,
					FailureReason: types.CreateAccountFailureReasonEmailAlreadyExists,
				},
			}, nil
		}
	}
	id := fmt.Sprintf("%012d", len(f.nodes))
	f.nodes = append(
		f.nodes,
		&node{id: id, name: *in.AccountName, email: *in.Email, parent: "r-abcd", kind: "account"},
	)
	return &organizations.CreateAccountOutput{CreateAccountStatus: &types.CreateAccountStatus{
		State: types.CreateAccountStateSucceeded, AccountId: aws.String(id),
	}}, nil
}

func (f *fakeOrg) CreateOrganizationalUnit(
	_ context.Context,
	in *organizations.CreateOrganizationalUnitInput,
	_ ...func(*organizations.Options),
) (*organizations.CreateOrganizationalUnitOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := fmt.Sprintf("ou-abcd-%08d", len(f.nodes))
	f.nodes = append(f.nodes, &node{id: id, name: *in.Name, parent: *in.ParentId, kind: "ou"})
	return &organizations.CreateOrganizationalUnitOutput{
		OrganizationalUnit: &types.OrganizationalUnit{Id: aws.String(id)},
	}, nil
}

func start(t *testing.T, f *fakeOrg) *consoletest.Browser {
	t.Helper()
	s := consoletest.Start(
		t,
		app.Overrides{Accounts: func(aws.Credentials) accounts.API { return f }},
		nil,
		"accounts",
	)
	b := s.Browser(t)
	b.SignIn(consoletest.KeyID, consoletest.Secret)
	return b
}

func TestTree(t *testing.T) {
	f := newFake()
	f.nodes = append(
		f.nodes,
		&node{id: "ou-abcd-11111111", name: "Workloads", parent: "r-abcd", kind: "ou"},
		&node{id: "ou-abcd-22222222", name: "Prod", parent: "ou-abcd-11111111", kind: "ou"},
		&node{
			id:     "111111111111",
			name:   "shop-prod",
			parent: "ou-abcd-22222222",
			kind:   "account",
			email:  "p@example.com",
		},
	)
	b := start(t, f)
	res := b.Get("/accounts")
	consoletest.RequireStatus(t, res, http.StatusOK)
	consoletest.RequireText(
		t,
		res,
		"o-abcdefghij",
		"Root",
		"Workloads",
		"Prod",
		"shop-prod",
		"p@example.com",
		"Management",
	)
	if consoletest.Find(res.Doc, consoletest.LinkTo("/accounts/account?id=111111111111")) == nil {
		t.Fatal("no link to the nested account")
	}
	// The OU form offers every root and unit as a parent.
	sel := consoletest.Find(res.Doc, consoletest.ByName("parentId"))
	if got := consoletest.Text(sel); got != "Root Workloads Prod" {
		t.Fatalf("parents %q", got)
	}
}

func TestAccountDetails(t *testing.T) {
	f := newFake()
	f.nodes[1].tags = []types.Tag{{Key: aws.String("team"), Value: aws.String("platform")}}
	b := start(t, f)
	res := b.Get("/accounts/account?id=000000000000")
	consoletest.RequireStatus(t, res, http.StatusOK)
	consoletest.RequireText(
		t,
		res,
		"Management",
		"management@example.com",
		"ACTIVE",
		"team",
		"platform",
		"r-abcd",
	)

	res = b.Get("/accounts/account?id=999999999999")
	consoletest.RequireText(t, res, "AccountNotFoundException")
}

func TestNoOrganization(t *testing.T) {
	f := newFake()
	f.exists = false
	b := start(t, f)
	res := b.Get("/accounts")
	consoletest.RequireStatus(t, res, http.StatusOK)
	consoletest.RequireText(t, res, "There is no organization yet")
	res = b.PostForm("/accounts/organization", nil)
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Created the organization.")
}

func TestCreateAccountAndOU(t *testing.T) {
	f := newFake()
	b := start(t, f)
	b.Get("/accounts")

	res := b.PostForm(
		"/accounts/accounts",
		url.Values{"name": {"dev"}, "email": {"dev@example.com"}},
	)
	consoletest.RequireStatus(t, res, http.StatusSeeOther)
	page := b.Get(res.Location())
	consoletest.RequireFlash(t, page, "ok", "Created account dev")
	consoletest.RequireText(t, page, "dev@example.com")

	res = b.PostForm(
		"/accounts/accounts",
		url.Values{"name": {"again"}, "email": {"dev@example.com"}},
	)
	consoletest.RequireFlash(t, b.Get(res.Location()), "error", "EMAIL_ALREADY_EXISTS")

	res = b.PostForm("/accounts/ous", url.Values{"parentId": {"r-abcd"}, "name": {"Sandbox"}})
	page = b.Get(res.Location())
	consoletest.RequireFlash(t, page, "ok", "Created unit Sandbox")
	consoletest.RequireText(t, page, "Sandbox")
}

func TestHostileTreeRendersInert(t *testing.T) {
	f := newFake()
	for i, h := range consoletest.Hostile {
		f.nodes = append(
			f.nodes,
			&node{id: fmt.Sprintf("ou-h-%d", i), name: h, parent: "r-abcd", kind: "ou"},
			&node{
				id: fmt.Sprintf(
					"2%011d",
					i,
				),
				name:   h,
				email:  h,
				parent: fmt.Sprintf("ou-h-%d", i),
				kind:   "account",
				tags:   []types.Tag{{Key: aws.String(h), Value: aws.String(h)}},
			},
		)
	}
	b := start(t, f)
	res := b.Get("/accounts")
	consoletest.RequireInert(t, res)
	consoletest.RequireText(t, res, consoletest.Hostile...)
	res = b.Get("/accounts/account?id=200000000000")
	consoletest.RequireInert(t, res)
	consoletest.RequireText(t, res, consoletest.Hostile[0])
}

// hollowOrg answers without the fields the pages read, as a faulty
// service could.
type hollowOrg struct{ *fakeOrg }

func (hollowOrg) DescribeOrganization(
	context.Context, *organizations.DescribeOrganizationInput, ...func(*organizations.Options),
) (*organizations.DescribeOrganizationOutput, error) {
	return &organizations.DescribeOrganizationOutput{}, nil
}

func (hollowOrg) DescribeAccount(
	context.Context, *organizations.DescribeAccountInput, ...func(*organizations.Options),
) (*organizations.DescribeAccountOutput, error) {
	return &organizations.DescribeAccountOutput{}, nil
}

func (hollowOrg) CreateAccount(
	context.Context, *organizations.CreateAccountInput, ...func(*organizations.Options),
) (*organizations.CreateAccountOutput, error) {
	return &organizations.CreateAccountOutput{}, nil
}

func (hollowOrg) CreateOrganizationalUnit(
	context.Context, *organizations.CreateOrganizationalUnitInput, ...func(*organizations.Options),
) (*organizations.CreateOrganizationalUnitOutput, error) {
	return &organizations.CreateOrganizationalUnitOutput{}, nil
}

func TestHollowAnswersAreErrors(t *testing.T) {
	f := newFake()
	s := consoletest.Start(t, app.Overrides{
		Accounts: func(aws.Credentials) accounts.API { return hollowOrg{f} },
	}, nil, "accounts")
	b := s.Browser(t)
	b.SignIn(consoletest.KeyID, consoletest.Secret)

	res := b.Get("/accounts")
	consoletest.RequireStatus(t, res, http.StatusBadGateway)
	consoletest.RequireText(t, res, "DescribeOrganization without its Organization")

	res = b.Get("/accounts/account?id=000000000000")
	consoletest.RequireStatus(t, res, http.StatusBadGateway)
	consoletest.RequireText(t, res, "DescribeAccount without its Account")

	res = b.PostForm("/accounts/accounts", url.Values{"name": {"x"}, "email": {"x@example.com"}})
	consoletest.RequireStatus(t, res, http.StatusSeeOther)
	consoletest.RequireFlash(
		t,
		b.Get(res.Location()),
		"error",
		"CreateAccount without its CreateAccountStatus",
	)

	res = b.PostForm("/accounts/ous", url.Values{"parentId": {"r-abcd"}, "name": {"x"}})
	consoletest.RequireStatus(t, res, http.StatusSeeOther)
	consoletest.RequireFlash(
		t,
		b.Get(res.Location()),
		"error",
		"CreateOrganizationalUnit without its OrganizationalUnit",
	)
}
