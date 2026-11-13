package functions

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/gasmod/gas"

	"tule.dev/console/internal/web"
)

// policyExample is the example a function without a policy shows in its
// empty form.
const policyExample = `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "InvokeFromPartner",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::111122223333:root"},
      "Action": "lambda:InvokeFunction",
      "Resource": "FUNCTION"
    }
  ]
}`

// loadPolicy reads the function's policy with GetPolicy, which answers
// ResourceNotFoundException for a function without one: the function
// itself was just read. Its RevisionId goes with every change, so a
// policy changed elsewhere since the page was read is not overwritten.
func loadPolicy(ctx context.Context, api Lambda, name, arn string) *web.Policy {
	p := &web.Policy{
		ID:           "function-policy",
		Action:       Path + "/function/policy",
		DeleteAction: Path + "/function/policy/delete",
		RemoveAction: Path + "/function/permission/remove",
		RemoveField:  "statementId",
		Fields:       []web.Field{{Name: "name", Value: name}, {Name: "arn", Value: arn}},
		Placeholder:  strings.ReplaceAll(policyExample, "FUNCTION", arn),
	}
	out, err := api.GetPolicy(ctx, &lambda.GetPolicyInput{FunctionName: aws.String(name)})
	switch {
	case web.Code(err) == "ResourceNotFoundException":
	case err != nil:
		p.ReadErr = web.ReadFailure(err)
	default:
		doc := aws.ToString(out.Policy)
		p.Exists = true
		p.Document = web.FormatJSON(doc)
		p.Statements = web.Statements(doc)
		p.Fields = append(
			p.Fields,
			web.Field{Name: "revision", Value: aws.ToString(out.RevisionId)},
		)
	}
	return p
}

// revision is the posted RevisionId, nil when the page had none.
func revision(c gas.Context) *string {
	if r := c.Request().PostForm.Get("revision"); r != "" {
		return aws.String(r)
	}
	return nil
}

// putPolicy stores the posted document as the function's policy with
// PutResourcePolicy, replacing what AddPermission built. A document
// functions refuses, such as InvalidParameterValueException, is shown next
// to the form with what was typed.
func (m *Module) putPolicy(c gas.Context) error {
	form := c.Request().PostForm
	name, doc := form.Get("name"), form.Get("document")
	var err error
	if strings.TrimSpace(doc) == "" {
		err = &web.BadInput{Message: "Enter the policy document."}
	} else {
		_, err = m.clients(c).Lambda.PutResourcePolicy(c, &lambda.PutResourcePolicyInput{
			ResourceArn: aws.String(form.Get("arn")),
			Policy:      aws.String(doc),
			RevisionId:  revision(c),
		})
	}
	if err != nil {
		return m.refused(c, name, doc, err)
	}
	return web.Done(c, functionLink(name), "Saved the policy of function "+name+".")
}

func (m *Module) deletePolicy(c gas.Context) error {
	form := c.Request().PostForm
	name := form.Get("name")
	_, err := m.clients(c).Lambda.DeleteResourcePolicy(c, &lambda.DeleteResourcePolicyInput{
		ResourceArn: aws.String(form.Get("arn")),
		RevisionId:  revision(c),
	})
	if err != nil {
		return m.refused(c, name, "", err)
	}
	return web.Done(c, functionLink(name), "Deleted the policy of function "+name+".")
}

// removePermission removes the statement whose Sid is the posted
// StatementId, as AddPermission wrote it or any other with a Sid.
func (m *Module) removePermission(c gas.Context) error {
	form := c.Request().PostForm
	name, id := form.Get("name"), form.Get("statementId")
	_, err := m.clients(c).Lambda.RemovePermission(c, &lambda.RemovePermissionInput{
		FunctionName: aws.String(name),
		StatementId:  aws.String(id),
		RevisionId:   revision(c),
	})
	if err != nil {
		return m.refused(c, name, "", err)
	}
	return web.Done(
		c,
		functionLink(name),
		"Removed statement "+id+" from the policy of function "+name+".",
	)
}

// refused shows the function's page with err next to its policy's form,
// and doc in it, or the stored document when doc is "".
func (m *Module) refused(c gas.Context, name, doc string, err error) error {
	v, lerr := m.load(c, name)
	if lerr != nil {
		return m.render.Fail(c, Key, name, lerr)
	}
	if doc == "" {
		doc = v.Policy.Document
	}
	status := v.Policy.Refuse(doc, err)
	return m.render.Render(c, web.Page{
		Name: "functions/function", Title: name, Section: Key, Data: v, Status: status,
	})
}
