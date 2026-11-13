package iam

import (
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/gasmod/gas"

	"tule.dev/console/internal/web"
)

func roleLink(name string) string {
	return web.Link(Path+"/role", "name", name)
}

// Role is an IAM role.
type Role struct {
	Created     time.Time
	Name        string
	ID          string
	ARN         string
	Path        string
	Description string
	Link        string
	// Trust is its trust policy, formatted.
	Trust      string
	MaxSession int32
}

func toRole(r types.Role) Role {
	name := aws.ToString(r.RoleName)
	return Role{
		Name:        name,
		ID:          aws.ToString(r.RoleId),
		ARN:         aws.ToString(r.Arn),
		Path:        aws.ToString(r.Path),
		Description: aws.ToString(r.Description),
		Created:     aws.ToTime(r.CreateDate),
		MaxSession:  aws.ToInt32(r.MaxSessionDuration),
		Trust:       FormatPolicy(aws.ToString(r.AssumeRolePolicyDocument)),
		Link:        roleLink(name),
	}
}

type rolesView struct {
	NextLink  string
	FirstLink string
	Roles     []Role
}

func (m *Module) roles(c gas.Context) error {
	marker := c.Query("marker")
	in := &iam.ListRolesInput{MaxItems: aws.Int32(pageSize)}
	if marker != "" {
		in.Marker = aws.String(marker)
	}
	out, err := m.client(c).ListRoles(c, in)
	if err != nil {
		return m.render.Fail(c, Key, "Roles", err)
	}
	v := rolesView{}
	for _, r := range out.Roles {
		v.Roles = append(v.Roles, toRole(r))
	}
	if out.IsTruncated && aws.ToString(out.Marker) != "" {
		v.NextLink = web.Link(Path+"/roles", "marker", aws.ToString(out.Marker))
	}
	if marker != "" {
		v.FirstLink = Path + "/roles"
	}
	return m.render.Render(c, web.Page{Name: "iam/roles", Title: "Roles", Section: Key, Data: v})
}

type roleView struct {
	Role
	Policies Policies
}

func (m *Module) role(c gas.Context) error {
	api := m.client(c)
	name := c.Query("name")
	out, err := api.GetRole(c, &iam.GetRoleInput{RoleName: aws.String(name)})
	if err != nil {
		return m.render.Fail(c, Key, name, err)
	}
	if out.Role == nil {
		return m.render.Fail(c, Key, name,
			&web.MissingField{Operation: "GetRole", Field: "its Role"})
	}
	v := roleView{Role: toRole(*out.Role)}
	v.Policies = loadPolicies(c, api, ownerOf(roleKind, v.Name))
	return m.render.Render(c, web.Page{Name: "iam/role", Title: v.Name, Section: Key, Data: v})
}

type newRoleView struct {
	Error       *web.Failure
	Name        string
	Path        string
	Description string
	Trust       string
	MaxSession  string
}

// trustAccount is the trust policy a new role starts from: the account's
// principals, as the IAM console's "AWS account" trusted entity is.
func trustAccount(account string) string {
	if account == "" {
		account = "<account>"
	}
	return `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::` + account + `:root"},
      "Action": "sts:AssumeRole"
    }
  ]
}`
}

func (m *Module) newRole(c gas.Context) error {
	account := ""
	if sess := web.FromContext(c); sess != nil {
		account = sess.Principal().Account
	}
	return m.renderNewRole(c, newRoleView{Trust: trustAccount(account)}, 0)
}

func (m *Module) renderNewRole(c gas.Context, v newRoleView, status int) error {
	return m.render.Render(c, web.Page{
		Name: "iam/newrole", Title: "New role", Section: Key, Data: v, Status: status,
	})
}

// createRole creates a role with its trust policy. A refusal, such as a
// MalformedPolicyDocument, is shown next to the form with what was typed.
func (m *Module) createRole(c gas.Context) error {
	form := c.Request().PostForm
	v := newRoleView{
		Name:        strings.TrimSpace(form.Get("name")),
		Path:        strings.TrimSpace(form.Get("path")),
		Description: strings.TrimSpace(form.Get("description")),
		Trust:       form.Get("trust"),
		MaxSession:  strings.TrimSpace(form.Get("maxSession")),
	}
	in := &iam.CreateRoleInput{
		RoleName:                 aws.String(v.Name),
		AssumeRolePolicyDocument: aws.String(v.Trust),
	}
	if v.Path != "" {
		in.Path = aws.String(v.Path)
	}
	if v.Description != "" {
		in.Description = aws.String(v.Description)
	}
	var err error
	switch {
	case v.Name == "":
		err = &web.BadInput{Message: "Enter a role name."}
	case strings.TrimSpace(v.Trust) == "":
		err = &web.BadInput{Message: "Enter the trust policy."}
	case v.MaxSession != "":
		n, perr := strconv.ParseInt(v.MaxSession, 10, 32)
		if perr != nil {
			err = &web.BadInput{Message: "The maximum session duration is a number of seconds."}
			break
		}
		in.MaxSessionDuration = aws.Int32(int32(n))
	}
	if err == nil {
		_, err = m.client(c).CreateRole(c, in)
	}
	if err != nil {
		f := web.Describe(err)
		v.Error = &f
		return m.renderNewRole(c, v, f.Status)
	}
	return web.Done(c, roleLink(v.Name), "Created role "+v.Name+".")
}

func (m *Module) deleteRole(c gas.Context) error {
	name := c.Request().PostForm.Get("name")
	if _, err := m.client(c).
		DeleteRole(c, &iam.DeleteRoleInput{RoleName: aws.String(name)}); err != nil {
		return web.Failed(c, roleLink(name), "Role "+name+" was not deleted", err)
	}
	return web.Done(c, Path+"/roles", "Deleted role "+name+".")
}
