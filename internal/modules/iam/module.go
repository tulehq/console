// Package iam is the identity section: IAM users with their access keys
// (status, created, last used), creating a user, creating a key (its
// secret shown once, as AWS does), activating, deactivating and deleting
// keys, and deleting users; each user's and role's inline policies (view,
// put, delete) and attached managed policies (attach, detach); roles with
// their trust policies (list, create, view, delete); and managed policies
// (list, create, view the default version's document, delete).
package iam

import (
	"context"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/gasmod/gas"

	"tule.dev/console/internal/web"
)

// Key is the section's key, and Path the path its pages live under.
const (
	Key  = "iam"
	Path = "/iam"
)

const (
	moduleName = "tule/modules/iam"
	// pageSize is how many users a page shows.
	pageSize = 50
)

// API is the part of the IAM client the section calls; *iam.Client is one.
type API interface {
	ListUsers(
		context.Context,
		*iam.ListUsersInput,
		...func(*iam.Options),
	) (*iam.ListUsersOutput, error)
	GetUser(context.Context, *iam.GetUserInput, ...func(*iam.Options)) (*iam.GetUserOutput, error)
	CreateUser(
		context.Context,
		*iam.CreateUserInput,
		...func(*iam.Options),
	) (*iam.CreateUserOutput, error)
	DeleteUser(
		context.Context,
		*iam.DeleteUserInput,
		...func(*iam.Options),
	) (*iam.DeleteUserOutput, error)
	ListAccessKeys(
		context.Context,
		*iam.ListAccessKeysInput,
		...func(*iam.Options),
	) (*iam.ListAccessKeysOutput, error)
	CreateAccessKey(
		context.Context, *iam.CreateAccessKeyInput, ...func(*iam.Options),
	) (*iam.CreateAccessKeyOutput, error)
	UpdateAccessKey(
		context.Context, *iam.UpdateAccessKeyInput, ...func(*iam.Options),
	) (*iam.UpdateAccessKeyOutput, error)
	DeleteAccessKey(
		context.Context, *iam.DeleteAccessKeyInput, ...func(*iam.Options),
	) (*iam.DeleteAccessKeyOutput, error)
	GetAccessKeyLastUsed(
		context.Context, *iam.GetAccessKeyLastUsedInput, ...func(*iam.Options),
	) (*iam.GetAccessKeyLastUsedOutput, error)
	ListUserTags(
		context.Context,
		*iam.ListUserTagsInput,
		...func(*iam.Options),
	) (*iam.ListUserTagsOutput, error)
	PolicyAPI
	RoleAPI
}

// PolicyAPI is the part of API that reads and changes policies: users'
// inline and attached policies, and managed policies.
type PolicyAPI interface {
	ListUserPolicies(
		context.Context, *iam.ListUserPoliciesInput, ...func(*iam.Options),
	) (*iam.ListUserPoliciesOutput, error)
	GetUserPolicy(
		context.Context, *iam.GetUserPolicyInput, ...func(*iam.Options),
	) (*iam.GetUserPolicyOutput, error)
	PutUserPolicy(
		context.Context, *iam.PutUserPolicyInput, ...func(*iam.Options),
	) (*iam.PutUserPolicyOutput, error)
	DeleteUserPolicy(
		context.Context, *iam.DeleteUserPolicyInput, ...func(*iam.Options),
	) (*iam.DeleteUserPolicyOutput, error)
	ListAttachedUserPolicies(
		context.Context, *iam.ListAttachedUserPoliciesInput, ...func(*iam.Options),
	) (*iam.ListAttachedUserPoliciesOutput, error)
	AttachUserPolicy(
		context.Context, *iam.AttachUserPolicyInput, ...func(*iam.Options),
	) (*iam.AttachUserPolicyOutput, error)
	DetachUserPolicy(
		context.Context, *iam.DetachUserPolicyInput, ...func(*iam.Options),
	) (*iam.DetachUserPolicyOutput, error)
	ListPolicies(
		context.Context, *iam.ListPoliciesInput, ...func(*iam.Options),
	) (*iam.ListPoliciesOutput, error)
	GetPolicy(
		context.Context, *iam.GetPolicyInput, ...func(*iam.Options),
	) (*iam.GetPolicyOutput, error)
	GetPolicyVersion(
		context.Context, *iam.GetPolicyVersionInput, ...func(*iam.Options),
	) (*iam.GetPolicyVersionOutput, error)
	CreatePolicy(
		context.Context, *iam.CreatePolicyInput, ...func(*iam.Options),
	) (*iam.CreatePolicyOutput, error)
	DeletePolicy(
		context.Context, *iam.DeletePolicyInput, ...func(*iam.Options),
	) (*iam.DeletePolicyOutput, error)
}

// RoleAPI is the part of API for roles and their policies.
type RoleAPI interface {
	ListRoles(
		context.Context, *iam.ListRolesInput, ...func(*iam.Options),
	) (*iam.ListRolesOutput, error)
	GetRole(context.Context, *iam.GetRoleInput, ...func(*iam.Options)) (*iam.GetRoleOutput, error)
	CreateRole(
		context.Context, *iam.CreateRoleInput, ...func(*iam.Options),
	) (*iam.CreateRoleOutput, error)
	DeleteRole(
		context.Context, *iam.DeleteRoleInput, ...func(*iam.Options),
	) (*iam.DeleteRoleOutput, error)
	ListRolePolicies(
		context.Context, *iam.ListRolePoliciesInput, ...func(*iam.Options),
	) (*iam.ListRolePoliciesOutput, error)
	GetRolePolicy(
		context.Context, *iam.GetRolePolicyInput, ...func(*iam.Options),
	) (*iam.GetRolePolicyOutput, error)
	PutRolePolicy(
		context.Context, *iam.PutRolePolicyInput, ...func(*iam.Options),
	) (*iam.PutRolePolicyOutput, error)
	DeleteRolePolicy(
		context.Context, *iam.DeleteRolePolicyInput, ...func(*iam.Options),
	) (*iam.DeleteRolePolicyOutput, error)
	ListAttachedRolePolicies(
		context.Context, *iam.ListAttachedRolePoliciesInput, ...func(*iam.Options),
	) (*iam.ListAttachedRolePoliciesOutput, error)
	AttachRolePolicy(
		context.Context, *iam.AttachRolePolicyInput, ...func(*iam.Options),
	) (*iam.AttachRolePolicyOutput, error)
	DetachRolePolicy(
		context.Context, *iam.DetachRolePolicyInput, ...func(*iam.Options),
	) (*iam.DetachRolePolicyOutput, error)
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
		g.Get("/", m.users)
		g.Post("/users", m.createUser)
		g.Get("/user", m.user)
		g.Post("/users/delete", m.deleteUser)
		g.Post("/keys", m.createKey)
		g.Post("/keys/status", m.keyStatus)
		g.Post("/keys/delete", m.deleteKey)
		for _, kind := range []string{userKind, roleKind} {
			g.Get("/"+kind+"/policy", m.inline)
			g.Post("/"+kind+"/policy", m.putInline)
			g.Post("/"+kind+"/policy/delete", m.deleteInline)
			g.Post("/"+kind+"/attach", m.attach)
			g.Post("/"+kind+"/detach", m.detach)
		}
		g.Get("/roles", m.roles)
		g.Get("/roles/new", m.newRole)
		g.Post("/roles", m.createRole)
		g.Get("/role", m.role)
		g.Post("/roles/delete", m.deleteRole)
		g.Get("/policies", m.policies)
		g.Get("/policies/new", m.newPolicy)
		g.Post("/policies", m.createPolicy)
		g.Get("/policy", m.policy)
		g.Post("/policies/delete", m.deletePolicy)
	})
	return nil
}

// Close releases nothing; the module holds no resources of its own.
func (m *Module) Close(context.Context) error { return nil }

func (m *Module) client(c gas.Context) API {
	return m.newClient(web.FromContext(c).Credentials())
}

func userLink(name string) string {
	return web.Link(Path+"/user", "name", name)
}

// AccessKey is a user's key.
type AccessKey struct {
	Created     time.Time
	LastUsed    time.Time
	ID          string
	Status      string
	LastService string
	LastRegion  string
}

// User is a user with its keys.
type User struct {
	Created time.Time
	Name    string
	ID      string
	ARN     string
	Path    string
	Link    string
	Keys    []AccessKey
}

type usersView struct {
	NextLink  string
	FirstLink string
	Users     []User
}

func (m *Module) users(c gas.Context) error {
	api := m.client(c)
	marker := c.Query("marker")
	in := &iam.ListUsersInput{MaxItems: aws.Int32(pageSize)}
	if marker != "" {
		in.Marker = aws.String(marker)
	}
	out, err := api.ListUsers(c, in)
	if err != nil {
		return m.render.Fail(c, Key, "Users", err)
	}
	v := usersView{}
	for _, u := range out.Users {
		user := toUser(u)
		if user.Keys, err = keys(c, api, user.Name); err != nil {
			return m.render.Fail(c, Key, "Users", err)
		}
		v.Users = append(v.Users, user)
	}
	if out.IsTruncated && aws.ToString(out.Marker) != "" {
		v.NextLink = web.Link(Path, "marker", aws.ToString(out.Marker))
	}
	if marker != "" {
		v.FirstLink = Path
	}
	return m.render.Render(c, web.Page{Name: "iam/users", Title: "Users", Section: Key, Data: v})
}

func toUser(u types.User) User {
	name := aws.ToString(u.UserName)
	return User{
		Name:    name,
		ID:      aws.ToString(u.UserId),
		ARN:     aws.ToString(u.Arn),
		Path:    aws.ToString(u.Path),
		Created: aws.ToTime(u.CreateDate),
		Link:    userLink(name),
	}
}

// keys lists user's keys, each with when it was last used.
func keys(ctx context.Context, api API, user string) ([]AccessKey, error) {
	var out []AccessKey
	in := &iam.ListAccessKeysInput{UserName: aws.String(user)}
	for {
		page, err := api.ListAccessKeys(ctx, in)
		if err != nil {
			return nil, err
		}
		for _, k := range page.AccessKeyMetadata {
			key := AccessKey{
				ID:      aws.ToString(k.AccessKeyId),
				Status:  string(k.Status),
				Created: aws.ToTime(k.CreateDate),
			}
			used, err := api.GetAccessKeyLastUsed(
				ctx,
				&iam.GetAccessKeyLastUsedInput{AccessKeyId: k.AccessKeyId},
			)
			if err != nil {
				return nil, err
			}
			if lu := used.AccessKeyLastUsed; lu != nil {
				key.LastUsed = aws.ToTime(lu.LastUsedDate)
				key.LastService = aws.ToString(lu.ServiceName)
				key.LastRegion = aws.ToString(lu.Region)
			}
			out = append(out, key)
		}
		if !page.IsTruncated || aws.ToString(page.Marker) == "" {
			return out, nil
		}
		in.Marker = page.Marker
	}
}

// Tag is a tag of a user.
type Tag struct {
	Key   string
	Value string
}

type userView struct {
	User
	Tags     []Tag
	Policies Policies
}

func (m *Module) user(c gas.Context) error {
	api := m.client(c)
	name := c.Query("name")
	out, err := api.GetUser(c, &iam.GetUserInput{UserName: aws.String(name)})
	if err != nil {
		return m.render.Fail(c, Key, name, err)
	}
	if out.User == nil {
		return m.render.Fail(
			c,
			Key,
			name,
			&web.MissingField{Operation: "GetUser", Field: "its User"},
		)
	}
	v := userView{User: toUser(*out.User)}
	if v.Keys, err = keys(c, api, v.Name); err != nil {
		return m.render.Fail(c, Key, name, err)
	}
	tags := &iam.ListUserTagsInput{UserName: aws.String(name)}
	for {
		t, terr := api.ListUserTags(c, tags)
		if terr != nil {
			return m.render.Fail(c, Key, name, terr)
		}
		for _, tag := range t.Tags {
			v.Tags = append(v.Tags, Tag{Key: aws.ToString(tag.Key), Value: aws.ToString(tag.Value)})
		}
		if !t.IsTruncated || aws.ToString(t.Marker) == "" {
			break
		}
		tags.Marker = t.Marker
	}
	v.Policies = loadPolicies(c, api, ownerOf(userKind, v.Name))
	return m.render.Render(c, web.Page{Name: "iam/user", Title: v.Name, Section: Key, Data: v})
}

func (m *Module) createUser(c gas.Context) error {
	form := c.Request().PostForm
	name := strings.TrimSpace(form.Get("name"))
	if name == "" {
		return web.Invalid(c, Path, "Enter a user name.")
	}
	in := &iam.CreateUserInput{UserName: aws.String(name)}
	if p := strings.TrimSpace(form.Get("path")); p != "" {
		in.Path = aws.String(p)
	}
	if _, err := m.client(c).CreateUser(c, in); err != nil {
		return web.Failed(c, Path, "User "+name+" was not created", err)
	}
	return web.Done(c, userLink(name), "Created user "+name+".")
}

func (m *Module) deleteUser(c gas.Context) error {
	name := c.Request().PostForm.Get("name")
	if _, err := m.client(c).
		DeleteUser(c, &iam.DeleteUserInput{UserName: aws.String(name)}); err != nil {
		return web.Failed(c, userLink(name), "User "+name+" was not deleted", err)
	}
	return web.Done(c, Path, "Deleted user "+name+".")
}

type newKeyView struct {
	User     string
	UserLink string
	ID       string
	Secret   string
}

// createKey creates a key and answers its secret in this response alone:
// the console keeps no copy, the page is not cached, and HTMX keeps it out
// of its history.
func (m *Module) createKey(c gas.Context) error {
	user := c.Request().PostForm.Get("user")
	out, err := m.client(c).
		CreateAccessKey(c, &iam.CreateAccessKeyInput{UserName: aws.String(user)})
	if err == nil && out.AccessKey == nil {
		err = &web.MissingField{Operation: "CreateAccessKey", Field: "its AccessKey"}
	}
	if err != nil {
		return web.Failed(c, userLink(user), "No key was created for "+user, err)
	}
	return m.render.Render(c, web.Page{
		Name: "iam/newkey", Title: "New access key", Section: Key,
		Data: newKeyView{
			User:     user,
			UserLink: userLink(user),
			ID:       aws.ToString(out.AccessKey.AccessKeyId),
			Secret:   aws.ToString(out.AccessKey.SecretAccessKey),
		},
	})
}

func (m *Module) keyStatus(c gas.Context) error {
	form := c.Request().PostForm
	user, id := form.Get("user"), form.Get("id")
	status := types.StatusType(form.Get("status"))
	if status != types.StatusTypeActive && status != types.StatusTypeInactive {
		return web.Invalid(c, userLink(user), "A key is Active or Inactive.")
	}
	_, err := m.client(c).UpdateAccessKey(c, &iam.UpdateAccessKeyInput{
		UserName: aws.String(user), AccessKeyId: aws.String(id), Status: status,
	})
	if err != nil {
		return web.Failed(c, userLink(user), "Key "+id+" was not changed", err)
	}
	word := "Activated"
	if status == types.StatusTypeInactive {
		word = "Deactivated"
	}
	return web.Done(c, userLink(user), word+" key "+id+".")
}

func (m *Module) deleteKey(c gas.Context) error {
	form := c.Request().PostForm
	user, id := form.Get("user"), form.Get("id")
	_, err := m.client(c).DeleteAccessKey(c, &iam.DeleteAccessKeyInput{
		UserName: aws.String(user), AccessKeyId: aws.String(id),
	})
	if err != nil {
		return web.Failed(c, userLink(user), "Key "+id+" was not deleted", err)
	}
	return web.Done(c, userLink(user), "Deleted key "+id+".")
}
