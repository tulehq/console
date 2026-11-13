package iam

import (
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/gasmod/gas"

	"tule.dev/console/internal/web"
)

func policyLink(arn string) string {
	return web.Link(Path+"/policy", "arn", arn)
}

// awsManaged reports whether arn is a policy AWS manages, which nobody
// changes or deletes.
func awsManaged(arn string) bool {
	return strings.HasPrefix(arn, "arn:aws:iam::aws:policy/")
}

// ManagedPolicy is a managed policy, AWS's or the account's.
type ManagedPolicy struct {
	Created        time.Time
	Updated        time.Time
	Name           string
	ID             string
	ARN            string
	Path           string
	Description    string
	DefaultVersion string
	Link           string
	// Document is the default version's, formatted.
	Document    string
	Attachments int32
	AWS         bool
}

func toManaged(p types.Policy) ManagedPolicy {
	arn := aws.ToString(p.Arn)
	return ManagedPolicy{
		Name:           aws.ToString(p.PolicyName),
		ID:             aws.ToString(p.PolicyId),
		ARN:            arn,
		Path:           aws.ToString(p.Path),
		Description:    aws.ToString(p.Description),
		DefaultVersion: aws.ToString(p.DefaultVersionId),
		Created:        aws.ToTime(p.CreateDate),
		Updated:        aws.ToTime(p.UpdateDate),
		Attachments:    aws.ToInt32(p.AttachmentCount),
		AWS:            awsManaged(arn),
		Link:           policyLink(arn),
	}
}

type policiesView struct {
	NextLink  string
	FirstLink string
	Policies  []ManagedPolicy
}

func (m *Module) policies(c gas.Context) error {
	marker := c.Query("marker")
	in := &iam.ListPoliciesInput{MaxItems: aws.Int32(pageSize), Scope: types.PolicyScopeTypeAll}
	if marker != "" {
		in.Marker = aws.String(marker)
	}
	out, err := m.client(c).ListPolicies(c, in)
	if err != nil {
		return m.render.Fail(c, Key, "Policies", err)
	}
	v := policiesView{}
	for _, p := range out.Policies {
		v.Policies = append(v.Policies, toManaged(p))
	}
	if out.IsTruncated && aws.ToString(out.Marker) != "" {
		v.NextLink = web.Link(Path+"/policies", "marker", aws.ToString(out.Marker))
	}
	if marker != "" {
		v.FirstLink = Path + "/policies"
	}
	return m.render.Render(
		c,
		web.Page{Name: "iam/policies", Title: "Policies", Section: Key, Data: v},
	)
}

// policy shows a managed policy and its default version's document.
func (m *Module) policy(c gas.Context) error {
	api := m.client(c)
	arn := c.Query("arn")
	out, err := api.GetPolicy(c, &iam.GetPolicyInput{PolicyArn: aws.String(arn)})
	if err != nil {
		return m.render.Fail(c, Key, arn, err)
	}
	if out.Policy == nil {
		return m.render.Fail(c, Key, arn,
			&web.MissingField{Operation: "GetPolicy", Field: "its Policy"})
	}
	v := toManaged(*out.Policy)
	ver, err := api.GetPolicyVersion(c, &iam.GetPolicyVersionInput{
		PolicyArn: aws.String(arn), VersionId: aws.String(v.DefaultVersion),
	})
	if err != nil {
		return m.render.Fail(c, Key, v.Name, err)
	}
	if ver.PolicyVersion == nil {
		return m.render.Fail(c, Key, v.Name,
			&web.MissingField{Operation: "GetPolicyVersion", Field: "its PolicyVersion"})
	}
	v.Document = FormatPolicy(aws.ToString(ver.PolicyVersion.Document))
	return m.render.Render(c, web.Page{Name: "iam/policy", Title: v.Name, Section: Key, Data: v})
}

type newPolicyView struct {
	Error       *web.Failure
	Name        string
	Path        string
	Description string
	Document    string
}

func (m *Module) newPolicy(c gas.Context) error {
	return m.renderNewPolicy(c, newPolicyView{Document: emptyPolicy}, 0)
}

func (m *Module) renderNewPolicy(c gas.Context, v newPolicyView, status int) error {
	return m.render.Render(c, web.Page{
		Name: "iam/newpolicy", Title: "New policy", Section: Key, Data: v, Status: status,
	})
}

// createPolicy creates a customer managed policy. A refusal, such as a
// MalformedPolicyDocument, is shown next to the form with what was typed.
func (m *Module) createPolicy(c gas.Context) error {
	form := c.Request().PostForm
	v := newPolicyView{
		Name:        strings.TrimSpace(form.Get("name")),
		Path:        strings.TrimSpace(form.Get("path")),
		Description: strings.TrimSpace(form.Get("description")),
		Document:    form.Get("document"),
	}
	var err error
	var out *iam.CreatePolicyOutput
	switch {
	case v.Name == "":
		err = &web.BadInput{Message: "Enter a policy name."}
	case strings.TrimSpace(v.Document) == "":
		err = &web.BadInput{Message: "Enter the policy document."}
	default:
		in := &iam.CreatePolicyInput{
			PolicyName: aws.String(v.Name), PolicyDocument: aws.String(v.Document),
		}
		if v.Path != "" {
			in.Path = aws.String(v.Path)
		}
		if v.Description != "" {
			in.Description = aws.String(v.Description)
		}
		out, err = m.client(c).CreatePolicy(c, in)
		if err == nil && out.Policy == nil {
			err = &web.MissingField{Operation: "CreatePolicy", Field: "its Policy"}
		}
	}
	if err != nil {
		f := web.Describe(err)
		v.Error = &f
		return m.renderNewPolicy(c, v, f.Status)
	}
	return web.Done(c, policyLink(aws.ToString(out.Policy.Arn)), "Created policy "+v.Name+".")
}

func (m *Module) deletePolicy(c gas.Context) error {
	arn := c.Request().PostForm.Get("arn")
	if _, err := m.client(c).
		DeletePolicy(c, &iam.DeletePolicyInput{PolicyArn: aws.String(arn)}); err != nil {
		return web.Failed(c, policyLink(arn), "Policy "+arn+" was not deleted", err)
	}
	return web.Done(c, Path+"/policies", "Deleted policy "+arn+".")
}
