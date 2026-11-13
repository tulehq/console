package secrets

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/gasmod/gas"

	"tule.dev/console/internal/web"
)

// policyExample is the example a secret without a policy shows in its
// empty form.
const policyExample = `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadValue",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::111122223333:root"},
      "Action": "secretsmanager:GetSecretValue",
      "Resource": "SECRET"
    }
  ]
}`

func newPolicy(name, arn string) *web.Policy {
	resource := arn
	if resource == "" {
		resource = "*"
	}
	return &web.Policy{
		ID:             "secret-policy",
		Action:         Path + "/secret/policy",
		DeleteAction:   Path + "/secret/policy/delete",
		ValidateAction: Path + "/secret/policy/validate",
		Fields:         []web.Field{{Name: "id", Value: name}},
		Placeholder:    strings.ReplaceAll(policyExample, "SECRET", resource),
		BlockPublicBox: true,
		BlockPublic:    true,
	}
}

// loadPolicy reads the secret's resource policy. GetResourcePolicy answers
// a secret without one with its name alone; a policy that cannot be read
// has the service's answer in its place.
func loadPolicy(ctx context.Context, api API, name, arn string) *web.Policy {
	p := newPolicy(name, arn)
	out, err := api.GetResourcePolicy(ctx, &secretsmanager.GetResourcePolicyInput{
		SecretId: aws.String(name),
	})
	switch {
	case err != nil:
		p.ReadErr = web.ReadFailure(err)
	case out.ResourcePolicy != nil:
		p.Exists = true
		p.Document = web.FormatJSON(aws.ToString(out.ResourcePolicy))
	}
	return p
}

// putPolicy attaches the posted policy to the secret, replacing its own,
// with BlockPublicPolicy as the form's box says. A document secret-store
// refuses, such as MalformedPolicyDocumentException or
// PublicPolicyException, is shown next to the form with what was typed.
func (m *Module) putPolicy(c gas.Context) error {
	form := c.Request().PostForm
	id, doc, block := form.Get("id"), form.Get("document"), form.Get("blockPublic") == "on"
	var err error
	if strings.TrimSpace(doc) == "" {
		err = &web.BadInput{Message: "Enter the policy document."}
	} else {
		_, err = m.client(c).PutResourcePolicy(c, &secretsmanager.PutResourcePolicyInput{
			SecretId:          aws.String(id),
			ResourcePolicy:    aws.String(doc),
			BlockPublicPolicy: aws.Bool(block),
		})
	}
	if err != nil {
		return m.showPolicy(
			c,
			id,
			doc,
			block,
			func(p *web.Policy) int { return p.Refuse(doc, err) },
		)
	}
	return web.Done(c, secretLink(id), "Saved the resource policy of secret "+id+".")
}

func (m *Module) deletePolicy(c gas.Context) error {
	id := c.Request().PostForm.Get("id")
	_, err := m.client(c).DeleteResourcePolicy(c, &secretsmanager.DeleteResourcePolicyInput{
		SecretId: aws.String(id),
	})
	if err != nil {
		return m.showPolicy(c, id, "", true, func(p *web.Policy) int {
			return p.Refuse(p.Document, err)
		})
	}
	return web.Done(c, secretLink(id), "Deleted the resource policy of secret "+id+".")
}

// validatePolicy checks the posted policy with ValidateResourcePolicy,
// without storing it, and shows the secret's page with what it found and
// the document as it was typed.
func (m *Module) validatePolicy(c gas.Context) error {
	form := c.Request().PostForm
	id, doc, block := form.Get("id"), form.Get("document"), form.Get("blockPublic") == "on"
	var out *secretsmanager.ValidateResourcePolicyOutput
	var err error
	if strings.TrimSpace(doc) == "" {
		err = &web.BadInput{Message: "Enter the policy document."}
	} else {
		out, err = m.client(c).
			ValidateResourcePolicy(c, &secretsmanager.ValidateResourcePolicyInput{
				SecretId:       aws.String(id),
				ResourcePolicy: aws.String(doc),
			})
	}
	return m.showPolicy(c, id, doc, block, func(p *web.Policy) int {
		if err != nil {
			return p.Refuse(doc, err)
		}
		p.ReadErr, p.Document = nil, doc
		p.Validation = &web.Validation{Passed: out.PolicyValidationPassed}
		for _, e := range out.ValidationErrors {
			p.Validation.Findings = append(p.Validation.Findings, web.Finding{
				Check: aws.ToString(e.CheckName), Message: aws.ToString(e.ErrorMessage),
			})
		}
		return 0
	})
}

// showPolicy shows the secret's page with its policy section changed by
// set, which returns the status to answer with, and the box as it was
// posted.
func (m *Module) showPolicy(
	c gas.Context, id, doc string, block bool, set func(*web.Policy) int,
) error {
	v, err := m.describe(c, id)
	if err != nil {
		return m.render.Fail(c, Key, id, err)
	}
	if v.Policy == nil {
		// A secret scheduled for deletion: the form is shown for the
		// answer, though the stored policy was not read.
		v.Policy = newPolicy(v.Name, v.ARN)
	}
	if doc != "" {
		v.Policy.BlockPublic = block
	}
	status := set(v.Policy)
	return m.render.Render(c, web.Page{
		Name: "secrets/secret", Title: v.Name, Section: Key, Data: v, Status: status,
	})
}
