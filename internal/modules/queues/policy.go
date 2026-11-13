package queues

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/gasmod/gas"

	"tule.dev/console/internal/web"
)

// policyAttribute is the queue attribute that holds its policy.
const policyAttribute = string(types.QueueAttributeNamePolicy)

// policyExample is the example a queue without a policy shows in its
// empty form.
const policyExample = `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SendFromPartner",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::111122223333:root"},
      "Action": "sqs:SendMessage",
      "Resource": "QUEUE"
    }
  ]
}`

// loadPolicy reads the queue's Policy attribute with the SQS API, so a
// principal that may not read it is shown the service's answer in its
// place, whatever the inspection API showed of the queue.
func loadPolicy(ctx context.Context, api SQS, name, arn string) *web.Policy {
	p := &web.Policy{
		ID:           "queue-policy",
		Action:       Path + "/queue/policy",
		DeleteAction: Path + "/queue/policy/delete",
		RemoveAction: Path + "/queue/permission/remove",
		RemoveField:  "label",
		Fields:       []web.Field{{Name: "name", Value: name}},
		Placeholder:  strings.ReplaceAll(policyExample, "QUEUE", arn),
	}
	out, err := api.GetQueueUrl(ctx, &sqs.GetQueueUrlInput{QueueName: aws.String(name)})
	var attrs *sqs.GetQueueAttributesOutput
	if err == nil {
		attrs, err = api.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{
			QueueUrl:       out.QueueUrl,
			AttributeNames: []types.QueueAttributeName{types.QueueAttributeNamePolicy},
		})
	}
	if err != nil {
		p.ReadErr = web.ReadFailure(err)
		return p
	}
	if doc := attrs.Attributes[policyAttribute]; doc != "" {
		p.Exists = true
		p.Document = web.FormatJSON(doc)
		p.Statements = web.Statements(doc)
	}
	return p
}

// putPolicy sets the queue's Policy attribute to the posted document. A
// document queues refuses, InvalidAttributeValue with the reason, is shown
// next to the form with what was typed.
func (m *Module) putPolicy(c gas.Context) error {
	form := c.Request().PostForm
	name, doc := form.Get("name"), form.Get("document")
	if strings.TrimSpace(doc) == "" {
		return m.refused(c, name, doc, &web.BadInput{Message: "Enter the policy document."})
	}
	if err := m.setPolicy(c, name, doc); err != nil {
		return m.refused(c, name, doc, err)
	}
	return web.Done(c, queueLink(name), "Saved the policy of queue "+name+".")
}

// deletePolicy removes the queue's policy, which SetQueueAttributes does
// for an empty Policy.
func (m *Module) deletePolicy(c gas.Context) error {
	name := c.Request().PostForm.Get("name")
	if err := m.setPolicy(c, name, ""); err != nil {
		return m.refused(c, name, "", err)
	}
	return web.Done(c, queueLink(name), "Deleted the policy of queue "+name+".")
}

func (m *Module) setPolicy(c gas.Context, name, doc string) error {
	api := m.clients(c).SQS
	u, err := queueURL(c, api, name)
	if err != nil {
		return err
	}
	_, err = api.SetQueueAttributes(c, &sqs.SetQueueAttributesInput{
		QueueUrl:   u,
		Attributes: map[string]string{policyAttribute: doc},
	})
	return err
}

// removePermission removes the policy's statement whose Sid is the posted
// label, as AddPermission wrote it or any other with a Sid.
func (m *Module) removePermission(c gas.Context) error {
	form := c.Request().PostForm
	name, label := form.Get("name"), form.Get("label")
	api := m.clients(c).SQS
	u, err := queueURL(c, api, name)
	if err == nil {
		_, err = api.RemovePermission(c, &sqs.RemovePermissionInput{
			QueueUrl: u, Label: aws.String(label),
		})
	}
	if err != nil {
		return m.refused(c, name, "", err)
	}
	return web.Done(
		c,
		queueLink(name),
		"Removed statement "+label+" from the policy of queue "+name+".",
	)
}

// refused shows the queue's page with err next to its policy's form, and
// doc in it, or the stored document when doc is "".
func (m *Module) refused(c gas.Context, name, doc string, err error) error {
	v, lerr := m.load(c, name, "", "", "")
	if lerr != nil {
		return m.render.Fail(c, Key, name, lerr)
	}
	if doc == "" {
		doc = v.Policy.Document
	}
	status := v.Policy.Refuse(doc, err)
	return m.render.Render(c, web.Page{
		Name: "queues/queue", Title: name, Section: Key, Data: v, Status: status,
	})
}
