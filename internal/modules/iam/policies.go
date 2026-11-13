package iam

import (
	"bytes"
	"context"
	"encoding/json"
	"net/url"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/gasmod/gas"

	"tule.dev/console/internal/web"
)

// The kinds of principal a policy is inline in or attached to, as they
// appear in paths and form fields.
const (
	userKind = "user"
	roleKind = "role"
)

// kindOf is the kind of owner the request's path is under: /iam/role/...
// for a role, else a user.
func kindOf(c gas.Context) string {
	if strings.HasPrefix(c.Request().URL.Path, Path+"/"+roleKind+"/") {
		return roleKind
	}
	return userKind
}

// maxChoices bounds the managed policies an attach form offers.
const maxChoices = 1000

// Owner is the IAM user or role whose policies a page shows.
type Owner struct {
	Kind string
	Name string
	// Link is the owner's page, ListLink and ListTitle the list it is in.
	Link      string
	ListLink  string
	ListTitle string
}

func ownerOf(kind, name string) Owner {
	if kind == roleKind {
		return Owner{
			Kind: roleKind, Name: name, Link: roleLink(name),
			ListLink: Path + "/roles", ListTitle: "Roles",
		}
	}
	return Owner{
		Kind: userKind, Name: name, Link: userLink(name),
		ListLink: Path, ListTitle: "Users",
	}
}

// inlineLink is the page of the owner's inline policy name, or of a new
// one for "".
func (o Owner) inlineLink(name string) string {
	return web.Link(Path+"/"+o.Kind+"/policy", o.Kind, o.Name, "name", name)
}

// InlinePolicy is an inline policy of an owner, by name.
type InlinePolicy struct {
	Name string
	Link string
}

// AttachedPolicy is a managed policy attached to an owner.
type AttachedPolicy struct {
	Name string
	ARN  string
	Link string
}

// Choice is a managed policy an attach form offers.
type Choice struct {
	Name string
	ARN  string
}

// Policies are an owner's inline and attached policies, and the managed
// policies it may attach. Each list that could not be read has the
// service's message instead, so a principal allowed to read the owner but
// not its policies is shown why.
type Policies struct {
	Owner       Owner
	NewLink     string
	InlineErr   string
	AttachedErr string
	ChoicesErr  string
	Inline      []InlinePolicy
	Attached    []AttachedPolicy
	Choices     []Choice
	Limit       int
	// Truncated is set when the account has more managed policies than
	// the list offers; the form then takes an ARN as well.
	Truncated bool
}

func loadPolicies(ctx context.Context, api API, o Owner) Policies {
	p := Policies{Owner: o, NewLink: o.inlineLink(""), Limit: maxChoices}
	names, err := listInline(ctx, api, o)
	if err != nil {
		p.InlineErr = web.Describe(err).Message
	}
	for _, n := range names {
		p.Inline = append(p.Inline, InlinePolicy{Name: n, Link: o.inlineLink(n)})
	}
	attached, err := listAttached(ctx, api, o)
	if err != nil {
		p.AttachedErr = web.Describe(err).Message
	}
	have := map[string]bool{}
	for _, a := range attached {
		arn := aws.ToString(a.PolicyArn)
		have[arn] = true
		p.Attached = append(p.Attached, AttachedPolicy{
			Name: aws.ToString(a.PolicyName), ARN: arn, Link: policyLink(arn),
		})
	}
	all, truncated, err := listManaged(ctx, api, maxChoices)
	p.Truncated = truncated
	if err != nil {
		p.ChoicesErr = web.Describe(err).Message
	}
	for _, m := range all {
		if arn := aws.ToString(m.Arn); !have[arn] {
			p.Choices = append(p.Choices, Choice{Name: aws.ToString(m.PolicyName), ARN: arn})
		}
	}
	return p
}

// listInline returns the names of the owner's inline policies.
func listInline(ctx context.Context, api API, o Owner) ([]string, error) {
	var names []string
	var marker *string
	for {
		var page []string
		var truncated bool
		var next *string
		switch o.Kind {
		case roleKind:
			out, err := api.ListRolePolicies(ctx,
				&iam.ListRolePoliciesInput{RoleName: aws.String(o.Name), Marker: marker})
			if err != nil {
				return nil, err
			}
			page, truncated, next = out.PolicyNames, out.IsTruncated, out.Marker
		default:
			out, err := api.ListUserPolicies(ctx,
				&iam.ListUserPoliciesInput{UserName: aws.String(o.Name), Marker: marker})
			if err != nil {
				return nil, err
			}
			page, truncated, next = out.PolicyNames, out.IsTruncated, out.Marker
		}
		names = append(names, page...)
		if !truncated || aws.ToString(next) == "" {
			return names, nil
		}
		marker = next
	}
}

// listAttached returns the managed policies attached to the owner.
func listAttached(ctx context.Context, api API, o Owner) ([]types.AttachedPolicy, error) {
	var all []types.AttachedPolicy
	var marker *string
	for {
		var page []types.AttachedPolicy
		var truncated bool
		var next *string
		switch o.Kind {
		case roleKind:
			out, err := api.ListAttachedRolePolicies(ctx,
				&iam.ListAttachedRolePoliciesInput{RoleName: aws.String(o.Name), Marker: marker})
			if err != nil {
				return nil, err
			}
			page, truncated, next = out.AttachedPolicies, out.IsTruncated, out.Marker
		default:
			out, err := api.ListAttachedUserPolicies(ctx,
				&iam.ListAttachedUserPoliciesInput{UserName: aws.String(o.Name), Marker: marker})
			if err != nil {
				return nil, err
			}
			page, truncated, next = out.AttachedPolicies, out.IsTruncated, out.Marker
		}
		all = append(all, page...)
		if !truncated || aws.ToString(next) == "" {
			return all, nil
		}
		marker = next
	}
}

// listManaged returns up to limit managed policies, AWS's and the
// account's, and whether there are more.
func listManaged(ctx context.Context, api API, limit int) ([]types.Policy, bool, error) {
	var all []types.Policy
	in := &iam.ListPoliciesInput{Scope: types.PolicyScopeTypeAll}
	for {
		out, err := api.ListPolicies(ctx, in)
		if err != nil {
			return nil, false, err
		}
		all = append(all, out.Policies...)
		more := out.IsTruncated && aws.ToString(out.Marker) != ""
		if len(all) > limit {
			return all[:limit], true, nil
		}
		if !more {
			return all, false, nil
		}
		if len(all) == limit {
			return all, true, nil
		}
		in.Marker = out.Marker
	}
}

// FormatPolicy returns a policy document as IAM answers it, URL-encoded,
// decoded and indented. A document that is not JSON is returned decoded
// as it is, so nothing of it is lost.
func FormatPolicy(doc string) string {
	if dec, err := url.QueryUnescape(doc); err == nil {
		doc = dec
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, []byte(doc), "", "  "); err != nil {
		return doc
	}
	return buf.String()
}

type inlineView struct {
	Error    *web.Failure
	Owner    Owner
	Name     string
	Document string
	New      bool
}

func (m *Module) renderInline(c gas.Context, v inlineView, status int) error {
	title := v.Name
	if v.New {
		title = "New inline policy"
	}
	return m.render.Render(c, web.Page{
		Name: "iam/inline", Title: title, Section: Key, Data: v, Status: status,
	})
}

// inline shows an inline policy's document to edit, or the form of a new
// one when the query names none.
func (m *Module) inline(c gas.Context) error {
	kind := kindOf(c)
	o := ownerOf(kind, c.Query(kind))
	name := c.Query("name")
	if name == "" {
		return m.renderInline(c, inlineView{Owner: o, New: true, Document: emptyPolicy}, 0)
	}
	doc, err := getInline(c, m.client(c), o, name)
	if err != nil {
		return m.render.Fail(c, Key, name, err)
	}
	return m.renderInline(
		c,
		inlineView{Owner: o, Name: name, Document: FormatPolicy(doc)},
		0,
	)
}

// emptyPolicy is the document a new identity policy starts from.
const emptyPolicy = `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [],
      "Resource": "*"
    }
  ]
}`

func getInline(ctx context.Context, api API, o Owner, name string) (string, error) {
	if o.Kind == roleKind {
		out, err := api.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
			RoleName: aws.String(o.Name), PolicyName: aws.String(name),
		})
		if err != nil {
			return "", err
		}
		return aws.ToString(out.PolicyDocument), nil
	}
	out, err := api.GetUserPolicy(ctx, &iam.GetUserPolicyInput{
		UserName: aws.String(o.Name), PolicyName: aws.String(name),
	})
	if err != nil {
		return "", err
	}
	return aws.ToString(out.PolicyDocument), nil
}

// putInline saves an inline policy. A document identity refuses, such as
// MalformedPolicyDocument, is shown next to the form with what was typed.
func (m *Module) putInline(c gas.Context) error {
	kind := kindOf(c)
	form := c.Request().PostForm
	o := ownerOf(kind, form.Get(kind))
	v := inlineView{
		Owner:    o,
		Name:     strings.TrimSpace(form.Get("name")),
		Document: form.Get("document"),
		New:      form.Get("new") == "true",
	}
	var err error
	switch {
	case v.Name == "":
		err = &web.BadInput{Message: "Enter a policy name."}
	case strings.TrimSpace(v.Document) == "":
		err = &web.BadInput{Message: "Enter the policy document."}
	case v.New:
		// PutUserPolicy and PutRolePolicy replace a policy of the name, so
		// a new one is checked against the names the owner has first.
		err = m.refuseTaken(c, o, v.Name)
	}
	if err == nil {
		err = m.put(c, o, v.Name, v.Document)
	}
	if err != nil {
		f := web.Describe(err)
		v.Error = &f
		return m.renderInline(c, v, f.Status)
	}
	return web.Done(c, o.Link, "Saved inline policy "+v.Name+" of "+o.Name+".")
}

// refuseTaken returns a BadInput when the owner has an inline policy named
// name, matched with its case as identity matches inline policy names.
func (m *Module) refuseTaken(c gas.Context, o Owner, name string) error {
	names, err := listInline(c, m.client(c), o)
	if err != nil {
		return err
	}
	if slices.Contains(names, name) {
		return &web.BadInput{Message: o.Name + " already has an inline policy named " + name +
			". Open it to change it, or choose another name."}
	}
	return nil
}

// put saves the owner's inline policy name, replacing one of that name.
func (m *Module) put(c gas.Context, o Owner, name, doc string) error {
	var err error
	switch o.Kind {
	case roleKind:
		_, err = m.client(c).PutRolePolicy(c, &iam.PutRolePolicyInput{
			RoleName: aws.String(o.Name), PolicyName: aws.String(name),
			PolicyDocument: aws.String(doc),
		})
	default:
		_, err = m.client(c).PutUserPolicy(c, &iam.PutUserPolicyInput{
			UserName: aws.String(o.Name), PolicyName: aws.String(name),
			PolicyDocument: aws.String(doc),
		})
	}
	return err
}

func (m *Module) deleteInline(c gas.Context) error {
	kind := kindOf(c)
	form := c.Request().PostForm
	o := ownerOf(kind, form.Get(kind))
	name := form.Get("name")
	var err error
	if kind == roleKind {
		_, err = m.client(c).DeleteRolePolicy(c, &iam.DeleteRolePolicyInput{
			RoleName: aws.String(o.Name), PolicyName: aws.String(name),
		})
	} else {
		_, err = m.client(c).DeleteUserPolicy(c, &iam.DeleteUserPolicyInput{
			UserName: aws.String(o.Name), PolicyName: aws.String(name),
		})
	}
	if err != nil {
		return web.Failed(c, o.inlineLink(name), "Inline policy "+name+" was not deleted", err)
	}
	return web.Done(c, o.Link, "Deleted inline policy "+name+" of "+o.Name+".")
}

func (m *Module) attach(c gas.Context) error {
	kind := kindOf(c)
	form := c.Request().PostForm
	o := ownerOf(kind, form.Get(kind))
	// A typed ARN, offered beside a list cut at maxChoices, wins over the
	// list's choice.
	arn := strings.TrimSpace(form.Get("arnTyped"))
	if arn == "" {
		arn = strings.TrimSpace(form.Get("arn"))
	}
	if arn == "" {
		return web.Invalid(c, o.Link, "Choose a policy to attach.")
	}
	var err error
	if kind == roleKind {
		_, err = m.client(c).AttachRolePolicy(c, &iam.AttachRolePolicyInput{
			RoleName: aws.String(o.Name), PolicyArn: aws.String(arn),
		})
	} else {
		_, err = m.client(c).AttachUserPolicy(c, &iam.AttachUserPolicyInput{
			UserName: aws.String(o.Name), PolicyArn: aws.String(arn),
		})
	}
	if err != nil {
		return web.Failed(c, o.Link, "Policy "+arn+" was not attached", err)
	}
	return web.Done(c, o.Link, "Attached "+arn+" to "+o.Name+".")
}

func (m *Module) detach(c gas.Context) error {
	kind := kindOf(c)
	form := c.Request().PostForm
	o := ownerOf(kind, form.Get(kind))
	arn := form.Get("arn")
	var err error
	if kind == roleKind {
		_, err = m.client(c).DetachRolePolicy(c, &iam.DetachRolePolicyInput{
			RoleName: aws.String(o.Name), PolicyArn: aws.String(arn),
		})
	} else {
		_, err = m.client(c).DetachUserPolicy(c, &iam.DetachUserPolicyInput{
			UserName: aws.String(o.Name), PolicyArn: aws.String(arn),
		})
	}
	if err != nil {
		return web.Failed(c, o.Link, "Policy "+arn+" was not detached", err)
	}
	return web.Done(c, o.Link, "Detached "+arn+" from "+o.Name+".")
}
