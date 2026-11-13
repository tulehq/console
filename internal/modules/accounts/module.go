// Package accounts is the accounts section: the organization and its tree
// of roots, organizational units and accounts, an account's details and
// tags, and creating an account or an organizational unit.
package accounts

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/gasmod/gas"

	"tule.dev/console/internal/web"
)

// Key is the section's key, and Path the path its pages live under.
const (
	Key  = "accounts"
	Path = "/accounts"
)

const (
	moduleName = "tule/modules/accounts"
	// maxNodes bounds the tree the page walks.
	maxNodes = 3000
)

// API is the part of the Organizations client the section calls;
// *organizations.Client is one.
type API interface {
	DescribeOrganization(
		context.Context, *organizations.DescribeOrganizationInput, ...func(*organizations.Options),
	) (*organizations.DescribeOrganizationOutput, error)
	CreateOrganization(
		context.Context, *organizations.CreateOrganizationInput, ...func(*organizations.Options),
	) (*organizations.CreateOrganizationOutput, error)
	ListRoots(
		context.Context, *organizations.ListRootsInput, ...func(*organizations.Options),
	) (*organizations.ListRootsOutput, error)
	ListOrganizationalUnitsForParent(
		context.Context, *organizations.ListOrganizationalUnitsForParentInput, ...func(*organizations.Options),
	) (*organizations.ListOrganizationalUnitsForParentOutput, error)
	ListAccountsForParent(
		context.Context, *organizations.ListAccountsForParentInput, ...func(*organizations.Options),
	) (*organizations.ListAccountsForParentOutput, error)
	DescribeAccount(
		context.Context, *organizations.DescribeAccountInput, ...func(*organizations.Options),
	) (*organizations.DescribeAccountOutput, error)
	ListParents(
		context.Context, *organizations.ListParentsInput, ...func(*organizations.Options),
	) (*organizations.ListParentsOutput, error)
	ListTagsForResource(
		context.Context, *organizations.ListTagsForResourceInput, ...func(*organizations.Options),
	) (*organizations.ListTagsForResourceOutput, error)
	CreateAccount(
		context.Context, *organizations.CreateAccountInput, ...func(*organizations.Options),
	) (*organizations.CreateAccountOutput, error)
	CreateOrganizationalUnit(
		context.Context, *organizations.CreateOrganizationalUnitInput, ...func(*organizations.Options),
	) (*organizations.CreateOrganizationalUnitOutput, error)
}

// NewClient returns the client for a session's credentials.
type NewClient func(aws.Credentials) API

// Module serves the section.
type Module struct {
	router    *gas.Router
	render    *web.Renderer
	newClient NewClient
}

// NewModule returns the module. It registers its routes when the app
// initializes it.
func NewModule(router *gas.Router, render *web.Renderer, newClient NewClient) *Module {
	return &Module{router: router, render: render, newClient: newClient}
}

// Name identifies the module to gas.
func (m *Module) Name() string { return moduleName }

// Init registers the module's routes.
func (m *Module) Init(context.Context) error {
	m.router.Route(m, Path, func(g *gas.RouteGroup) {
		g.Get("/", m.tree)
		g.Post("/organization", m.createOrganization)
		g.Get("/account", m.account)
		g.Post("/accounts", m.createAccount)
		g.Post("/ous", m.createOU)
	})
	return nil
}

// Close releases nothing; the module holds no resources of its own.
func (m *Module) Close(context.Context) error { return nil }

func (m *Module) client(c gas.Context) API {
	return m.newClient(web.FromContext(c).Credentials())
}

func accountLink(id string) string {
	return web.Link(Path+"/account", "id", id)
}

// Node is a root, an organizational unit or an account in the tree.
type Node struct {
	ID       string
	Name     string
	Kind     string // root, ou or account
	ARN      string
	Email    string
	State    string
	Link     string
	Children []Node
	Depth    int
}

// Parent is a root or an organizational unit an OU can be created under.
type Parent struct {
	ID   string
	Name string
}

type treeView struct {
	ID          string
	ARN         string
	FeatureSet  string
	MasterID    string
	MasterEmail string
	Roots       []Node
	Parents     []Parent
	NoOrg       bool
	Truncated   bool
}

func (m *Module) tree(c gas.Context) error {
	api := m.client(c)
	org, err := api.DescribeOrganization(c, &organizations.DescribeOrganizationInput{})
	var notInUse *types.AWSOrganizationsNotInUseException
	if errors.As(err, &notInUse) {
		return m.render.Render(c, web.Page{
			Name: "accounts/tree", Title: "Organization", Section: Key, Data: treeView{NoOrg: true},
		})
	}
	if err == nil && org.Organization == nil {
		err = &web.MissingField{Operation: "DescribeOrganization", Field: "its Organization"}
	}
	if err != nil {
		return m.render.Fail(c, Key, "Organization", err)
	}
	v := treeView{
		ID:          aws.ToString(org.Organization.Id),
		ARN:         aws.ToString(org.Organization.Arn),
		FeatureSet:  string(org.Organization.FeatureSet),
		MasterID:    aws.ToString(org.Organization.MasterAccountId),
		MasterEmail: aws.ToString(org.Organization.MasterAccountEmail),
	}
	w := walker{api: api}
	in := &organizations.ListRootsInput{}
	for {
		out, lerr := api.ListRoots(c, in)
		if lerr != nil {
			return m.render.Fail(c, Key, "Organization", lerr)
		}
		for _, r := range out.Roots {
			node := Node{
				ID:   aws.ToString(r.Id),
				Name: aws.ToString(r.Name),
				Kind: "root",
				ARN:  aws.ToString(r.Arn),
			}
			v.Parents = append(v.Parents, Parent{ID: node.ID, Name: node.Name})
			if err = w.children(c, &node, &v.Parents); err != nil {
				return m.render.Fail(c, Key, "Organization", err)
			}
			v.Roots = append(v.Roots, node)
		}
		if aws.ToString(out.NextToken) == "" {
			break
		}
		in.NextToken = out.NextToken
	}
	v.Truncated = w.truncated
	return m.render.Render(
		c,
		web.Page{Name: "accounts/tree", Title: "Organization", Section: Key, Data: v},
	)
}

// walker walks the tree under a root, up to maxNodes nodes.
type walker struct {
	api       API
	nodes     int
	truncated bool
}

// children fills node's children: its organizational units, each with
// theirs, and then its accounts. Each OU is added to parents.
func (w *walker) children(ctx context.Context, node *Node, parents *[]Parent) error {
	if err := w.units(ctx, node, parents); err != nil {
		return err
	}
	return w.accounts(ctx, node)
}

// units adds node's organizational units, each with its own children.
func (w *walker) units(ctx context.Context, node *Node, parents *[]Parent) error {
	in := &organizations.ListOrganizationalUnitsForParentInput{ParentId: aws.String(node.ID)}
	for {
		out, err := w.api.ListOrganizationalUnitsForParent(ctx, in)
		if err != nil {
			return err
		}
		for _, ou := range out.OrganizationalUnits {
			if w.full() {
				return nil
			}
			child := Node{
				ID: aws.ToString(ou.Id), Name: aws.ToString(ou.Name), Kind: "ou",
				ARN: aws.ToString(ou.Arn), Depth: node.Depth + 1,
			}
			*parents = append(*parents, Parent{
				ID: child.ID, Name: strings.Repeat("  ", child.Depth) + child.Name,
			})
			if err = w.children(ctx, &child, parents); err != nil {
				return err
			}
			node.Children = append(node.Children, child)
		}
		if aws.ToString(out.NextToken) == "" {
			return nil
		}
		in.NextToken = out.NextToken
	}
}

// accounts adds node's accounts.
func (w *walker) accounts(ctx context.Context, node *Node) error {
	in := &organizations.ListAccountsForParentInput{ParentId: aws.String(node.ID)}
	for {
		out, err := w.api.ListAccountsForParent(ctx, in)
		if err != nil {
			return err
		}
		for _, a := range out.Accounts {
			if w.full() {
				return nil
			}
			id := aws.ToString(a.Id)
			node.Children = append(node.Children, Node{
				ID: id, Name: aws.ToString(a.Name), Kind: "account", ARN: aws.ToString(a.Arn),
				Email: aws.ToString(a.Email), State: accountState(a), Link: accountLink(id),
				Depth: node.Depth + 1,
			})
		}
		if aws.ToString(out.NextToken) == "" {
			return nil
		}
		in.NextToken = out.NextToken
	}
}

func (w *walker) full() bool {
	w.nodes++
	if w.nodes > maxNodes {
		w.truncated = true
		return true
	}
	return false
}

// accountState is the account's State, or its older Status when the
// service reports no State.
func accountState(a types.Account) string {
	if a.State != "" {
		return string(a.State)
	}
	return string(a.Status) //nolint:staticcheck // Status is deprecated, reported by older services
}

func (m *Module) createOrganization(c gas.Context) error {
	_, err := m.client(c).CreateOrganization(c, &organizations.CreateOrganizationInput{
		FeatureSet: types.OrganizationFeatureSetAll,
	})
	if err != nil {
		return web.Failed(c, Path, "The organization was not created", err)
	}
	return web.Done(c, Path, "Created the organization.")
}

// Tag is a tag of an account.
type Tag struct {
	Key   string
	Value string
}

type accountView struct {
	Joined  time.Time
	ID      string
	Name    string
	Email   string
	ARN     string
	State   string
	Method  string
	Parents []Parent
	Tags    []Tag
}

func (m *Module) account(c gas.Context) error {
	id := c.Query("id")
	api := m.client(c)
	out, err := api.DescribeAccount(
		c,
		&organizations.DescribeAccountInput{AccountId: aws.String(id)},
	)
	if err != nil {
		return m.render.Fail(c, Key, id, err)
	}
	a := out.Account
	if a == nil {
		return m.render.Fail(
			c,
			Key,
			id,
			&web.MissingField{Operation: "DescribeAccount", Field: "its Account"},
		)
	}
	v := accountView{
		ID: aws.ToString(a.Id), Name: aws.ToString(a.Name), Email: aws.ToString(a.Email),
		ARN: aws.ToString(a.Arn), State: accountState(*a), Method: string(a.JoinedMethod),
		Joined: aws.ToTime(a.JoinedTimestamp),
	}
	parents, err := api.ListParents(c, &organizations.ListParentsInput{ChildId: aws.String(id)})
	if err != nil {
		return m.render.Fail(c, Key, id, err)
	}
	for _, p := range parents.Parents {
		v.Parents = append(v.Parents, Parent{ID: aws.ToString(p.Id), Name: string(p.Type)})
	}
	tags := &organizations.ListTagsForResourceInput{ResourceId: aws.String(id)}
	for {
		t, terr := api.ListTagsForResource(c, tags)
		if terr != nil {
			return m.render.Fail(c, Key, id, terr)
		}
		for _, tag := range t.Tags {
			v.Tags = append(v.Tags, Tag{Key: aws.ToString(tag.Key), Value: aws.ToString(tag.Value)})
		}
		if aws.ToString(t.NextToken) == "" {
			break
		}
		tags.NextToken = t.NextToken
	}
	return m.render.Render(
		c,
		web.Page{Name: "accounts/account", Title: v.Name, Section: Key, Data: v},
	)
}

func (m *Module) createAccount(c gas.Context) error {
	form := c.Request().PostForm
	name, email := strings.TrimSpace(form.Get("name")), strings.TrimSpace(form.Get("email"))
	if name == "" || email == "" {
		return web.Invalid(c, Path, "Enter the account's name and email.")
	}
	out, err := m.client(c).CreateAccount(c, &organizations.CreateAccountInput{
		AccountName: aws.String(name),
		Email:       aws.String(email),
	})
	if err != nil {
		return web.Failed(c, Path, "Account "+name+" was not created", err)
	}
	st := out.CreateAccountStatus
	if st == nil {
		return web.Failed(c, Path, "Account "+name+" was not created",
			&web.MissingField{Operation: "CreateAccount", Field: "its CreateAccountStatus"})
	}
	switch st.State {
	case types.CreateAccountStateFailed:
		return web.Invalid(c, Path, "Account "+name+" was not created: "+string(st.FailureReason))
	case types.CreateAccountStateSucceeded:
		id := aws.ToString(st.AccountId)
		return web.Done(c, accountLink(id), "Created account "+name+" ("+id+").")
	default:
		return web.Done(c, Path, "Account "+name+" is being created ("+string(st.State)+").")
	}
}

func (m *Module) createOU(c gas.Context) error {
	form := c.Request().PostForm
	parent, name := form.Get("parentId"), strings.TrimSpace(form.Get("name"))
	if parent == "" || name == "" {
		return web.Invalid(c, Path, "Choose a parent and enter the unit's name.")
	}
	out, err := m.client(c).
		CreateOrganizationalUnit(c, &organizations.CreateOrganizationalUnitInput{
			ParentId: aws.String(parent),
			Name:     aws.String(name),
		})
	if err != nil {
		return web.Failed(c, Path, "Unit "+name+" was not created", err)
	}
	if out.OrganizationalUnit == nil {
		return web.Failed(
			c,
			Path,
			"Unit "+name+" may not have been created",
			&web.MissingField{
				Operation: "CreateOrganizationalUnit",
				Field:     "its OrganizationalUnit",
			},
		)
	}
	return web.Done(c, Path, "Created unit "+name+" ("+aws.ToString(out.OrganizationalUnit.Id)+").")
}
