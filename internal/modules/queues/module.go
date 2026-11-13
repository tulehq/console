// Package queues is the queues section: the queues with their counts and
// attributes, a queue's messages through the inspection API filtered by
// state and group, sending a message, purging a queue, and creating and
// deleting queues.
package queues

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/gasmod/gas"

	"tule.dev/console/internal/web"
)

// Key is the section's key, and Path the path its pages live under.
const (
	Key  = "sqs"
	Path = "/sqs"
)

const (
	moduleName = "tule/modules/queues"
	// pageSize is how many messages a page shows.
	pageSize = "50"
)

// SQS is the part of the SQS client the section calls; *sqs.Client is one.
type SQS interface {
	CreateQueue(
		context.Context,
		*sqs.CreateQueueInput,
		...func(*sqs.Options),
	) (*sqs.CreateQueueOutput, error)
	DeleteQueue(
		context.Context,
		*sqs.DeleteQueueInput,
		...func(*sqs.Options),
	) (*sqs.DeleteQueueOutput, error)
	PurgeQueue(
		context.Context,
		*sqs.PurgeQueueInput,
		...func(*sqs.Options),
	) (*sqs.PurgeQueueOutput, error)
	SendMessage(
		context.Context,
		*sqs.SendMessageInput,
		...func(*sqs.Options),
	) (*sqs.SendMessageOutput, error)
	GetQueueUrl(
		context.Context,
		*sqs.GetQueueUrlInput,
		...func(*sqs.Options),
	) (*sqs.GetQueueUrlOutput, error)
}

// Clients are the two APIs the section calls.
type Clients struct {
	Inspect Inspector
	SQS     SQS
}

// NewClients returns the clients for a session's credentials.
type NewClients func(aws.Credentials) Clients

// Module serves the section.
type Module struct {
	router     *gas.Router
	render     *web.Renderer
	newClients NewClients
}

// NewModule returns the module. It registers its routes when the app
// initializes it.
func NewModule(router *gas.Router, render *web.Renderer, newClients NewClients) *Module {
	return &Module{router: router, render: render, newClients: newClients}
}

// Name identifies the module to gas.
func (m *Module) Name() string { return moduleName }

// Init registers the module's routes.
func (m *Module) Init(context.Context) error {
	m.router.Route(m, Path, func(g *gas.RouteGroup) {
		g.Get("/", m.queues)
		g.Post("/queues", m.create)
		g.Get("/queue", m.queue)
		g.Post("/queue/send", m.send)
		g.Post("/queue/purge", m.purge)
		g.Post("/queue/delete", m.remove)
	})
	return nil
}

// Close releases nothing; the module holds no resources of its own.
func (m *Module) Close(context.Context) error { return nil }

func (m *Module) clients(c gas.Context) Clients {
	return m.newClients(web.FromContext(c).Credentials())
}

func queueLink(name string) string {
	return web.Link(Path+"/queue", "name", name)
}

// Row is a queue in the list.
type Row struct {
	Link string
	Queue
	FIFO bool
}

type queuesView struct {
	Queues []Row
}

func (m *Module) queues(c gas.Context) error {
	qs, err := m.clients(c).Inspect.Queues(c)
	if err != nil {
		return m.render.Fail(c, Key, "Queues", err)
	}
	v := queuesView{}
	for _, q := range qs {
		v.Queues = append(
			v.Queues,
			Row{Queue: q, Link: queueLink(q.Name), FIFO: q.Attributes["FifoQueue"] == "true"},
		)
	}
	return m.render.Render(
		c,
		web.Page{Name: "queues/queues", Title: "Queues", Section: Key, Data: v},
	)
}

// Attr is a name and a value.
type Attr struct {
	Name  string
	Value string
}

// MessageRow is a message in a queue's list.
type MessageRow struct {
	Message
	SentAt     time.Time
	VisibleAt  time.Time
	System     []Attr
	Attributes []Attr
}

type queueView struct {
	State      string
	Group      string
	NextLink   string
	FirstLink  string
	Attributes []Attr
	Messages   []MessageRow
	Queue      Queue
	FIFO       bool
}

func (m *Module) queue(c gas.Context) error {
	name, state, group := c.Query("name"), c.Query("state"), c.Query("group")
	cl := m.clients(c)
	qs, err := cl.Inspect.Queues(c)
	if err != nil {
		return m.render.Fail(c, Key, name, err)
	}
	v := queueView{State: state, Group: group}
	i := slices.IndexFunc(qs, func(q Queue) bool { return q.Name == name })
	if i < 0 {
		return m.render.Fail(c, Key, name,
			&web.NotFoundError{Message: "There is no queue named " + name + "."})
	}
	v.Queue = qs[i]
	v.FIFO = v.Queue.Attributes["FifoQueue"] == "true"
	v.Attributes = sorted(v.Queue.Attributes)

	query := url.Values{"limit": {pageSize}}
	for k, val := range map[string]string{"state": state, "group": group, "cursor": c.Query("cursor")} {
		if val != "" {
			query.Set(k, val)
		}
	}
	p, err := cl.Inspect.Messages(c, name, query)
	if err != nil {
		return m.render.Fail(c, Key, name, err)
	}
	for _, msg := range p.Items {
		v.Messages = append(v.Messages, messageRow(msg))
	}
	if p.NextCursor != "" {
		v.NextLink = web.Link(
			Path+"/queue",
			"name",
			name,
			"state",
			state,
			"group",
			group,
			"cursor",
			p.NextCursor,
		)
	}
	if c.Query("cursor") != "" {
		v.FirstLink = web.Link(Path+"/queue", "name", name, "state", state, "group", group)
	}
	return m.render.Render(c, web.Page{Name: "queues/queue", Title: name, Section: Key, Data: v})
}

// messageRow is msg as the queue's page lists it, its attributes sorted.
func messageRow(msg Message) MessageRow {
	row := MessageRow{Message: msg, System: sorted(msg.Attributes)}
	row.SentAt, _ = time.Parse(time.RFC3339Nano, msg.SentTime)
	row.VisibleAt, _ = time.Parse(time.RFC3339Nano, msg.VisibleAt)
	for name, a := range msg.MessageAttributes {
		val := a.StringValue
		if a.BinaryValue != "" {
			val = a.BinaryValue + " (base64)"
		}
		row.Attributes = append(
			row.Attributes,
			Attr{Name: name + " (" + a.DataType + ")", Value: val},
		)
	}
	sort.Slice(
		row.Attributes,
		func(i, j int) bool { return row.Attributes[i].Name < row.Attributes[j].Name },
	)
	return row
}

func sorted(m map[string]string) []Attr {
	out := make([]Attr, 0, len(m))
	for k, v := range m {
		out = append(out, Attr{Name: k, Value: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (m *Module) create(c gas.Context) error {
	form := c.Request().PostForm
	name := strings.TrimSpace(form.Get("name"))
	if name == "" {
		return web.Invalid(c, Path, "Enter a queue name.")
	}
	in := &sqs.CreateQueueInput{QueueName: aws.String(name), Attributes: map[string]string{}}
	if form.Get("fifo") == "on" {
		if !strings.HasSuffix(name, ".fifo") {
			name += ".fifo"
			in.QueueName = aws.String(name)
		}
		in.Attributes[string(types.QueueAttributeNameFifoQueue)] = "true"
		if form.Get("contentDedup") == "on" {
			in.Attributes[string(types.QueueAttributeNameContentBasedDeduplication)] = "true"
		}
	}
	if _, err := m.clients(c).SQS.CreateQueue(c, in); err != nil {
		return web.Failed(c, Path, "Queue "+name+" was not created", err)
	}
	return web.Done(c, queueLink(name), "Created queue "+name+".")
}

// queueURL resolves name to its URL.
func queueURL(c gas.Context, api SQS, name string) (*string, error) {
	out, err := api.GetQueueUrl(c, &sqs.GetQueueUrlInput{QueueName: aws.String(name)})
	if err != nil {
		return nil, err
	}
	return out.QueueUrl, nil
}

// parseAttributes reads the message attributes field: one Name=Value per
// line, each a String attribute.
func parseAttributes(s string) (map[string]types.MessageAttributeValue, error) {
	out := map[string]types.MessageAttributeValue{}
	for line := range strings.Lines(s) {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		name, value, ok := strings.Cut(line, "=")
		name = strings.TrimSpace(name)
		if !ok || name == "" {
			return nil, fmt.Errorf("attribute %q is not Name=Value", line)
		}
		out[name] = types.MessageAttributeValue{
			DataType:    aws.String("String"),
			StringValue: aws.String(value),
		}
	}
	return out, nil
}

func (m *Module) send(c gas.Context) error {
	form := c.Request().PostForm
	name := form.Get("name")
	target := queueLink(name)
	attrs, err := parseAttributes(form.Get("attributes"))
	if err != nil {
		return web.Invalid(c, target, "The message was not sent: "+err.Error()+".")
	}
	api := m.clients(c).SQS
	u, err := queueURL(c, api, name)
	if err != nil {
		return web.Failed(c, target, "The message was not sent", err)
	}
	in := &sqs.SendMessageInput{QueueUrl: u, MessageBody: aws.String(form.Get("body"))}
	if len(attrs) > 0 {
		in.MessageAttributes = attrs
	}
	if d := strings.TrimSpace(form.Get("delay")); d != "" {
		n, perr := strconv.ParseInt(d, 10, 32)
		if perr != nil {
			return web.Invalid(c, target, "The delay is a whole number of seconds.")
		}
		in.DelaySeconds = int32(n)
	}
	if g := strings.TrimSpace(form.Get("groupId")); g != "" {
		in.MessageGroupId = aws.String(g)
	}
	if d := strings.TrimSpace(form.Get("dedupId")); d != "" {
		in.MessageDeduplicationId = aws.String(d)
	}
	out, err := api.SendMessage(c, in)
	if err != nil {
		return web.Failed(c, target, "The message was not sent", err)
	}
	return web.Done(c, target, "Sent message "+aws.ToString(out.MessageId)+".")
}

func (m *Module) purge(c gas.Context) error {
	name := c.Request().PostForm.Get("name")
	api := m.clients(c).SQS
	u, err := queueURL(c, api, name)
	if err == nil {
		_, err = api.PurgeQueue(c, &sqs.PurgeQueueInput{QueueUrl: u})
	}
	if err != nil {
		return web.Failed(c, queueLink(name), "Queue "+name+" was not purged", err)
	}
	return web.Done(c, queueLink(name), "Purged queue "+name+".")
}

func (m *Module) remove(c gas.Context) error {
	name := c.Request().PostForm.Get("name")
	api := m.clients(c).SQS
	u, err := queueURL(c, api, name)
	if err == nil {
		_, err = api.DeleteQueue(c, &sqs.DeleteQueueInput{QueueUrl: u})
	}
	if err != nil {
		return web.Failed(c, queueLink(name), "Queue "+name+" was not deleted", err)
	}
	return web.Done(c, Path, "Deleted queue "+name+".")
}
