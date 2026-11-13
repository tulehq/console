// Package functions is the functions section: the functions with their
// state and configuration, invoking one with a JSON payload to see its
// result and log tail, the invocation history with its filters and each
// invocation's payload, result and log, and the event source mappings with
// their state, enabled and disabled from here.
package functions

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/gasmod/gas"

	"tule.dev/console/internal/web"
)

// Key is the section's key, and Path the path its pages live under.
const (
	Key  = "lambda"
	Path = "/lambda"
)

const (
	moduleName = "tule/modules/functions"
	// pageSize is how many functions or invocations a page shows.
	pageSize = 50
	// recent is how many invocations a function's page shows.
	recent = 10
)

// Lambda is the part of the Lambda client the section calls;
// *lambda.Client is one.
type Lambda interface {
	ListFunctions(
		context.Context,
		*lambda.ListFunctionsInput,
		...func(*lambda.Options),
	) (*lambda.ListFunctionsOutput, error)
	GetFunction(
		context.Context,
		*lambda.GetFunctionInput,
		...func(*lambda.Options),
	) (*lambda.GetFunctionOutput, error)
	Invoke(
		context.Context,
		*lambda.InvokeInput,
		...func(*lambda.Options),
	) (*lambda.InvokeOutput, error)
	ListEventSourceMappings(
		context.Context, *lambda.ListEventSourceMappingsInput, ...func(*lambda.Options),
	) (*lambda.ListEventSourceMappingsOutput, error)
	UpdateEventSourceMapping(
		context.Context, *lambda.UpdateEventSourceMappingInput, ...func(*lambda.Options),
	) (*lambda.UpdateEventSourceMappingOutput, error)
	GetPolicy(
		context.Context, *lambda.GetPolicyInput, ...func(*lambda.Options),
	) (*lambda.GetPolicyOutput, error)
	PutResourcePolicy(
		context.Context, *lambda.PutResourcePolicyInput, ...func(*lambda.Options),
	) (*lambda.PutResourcePolicyOutput, error)
	DeleteResourcePolicy(
		context.Context, *lambda.DeleteResourcePolicyInput, ...func(*lambda.Options),
	) (*lambda.DeleteResourcePolicyOutput, error)
	RemovePermission(
		context.Context, *lambda.RemovePermissionInput, ...func(*lambda.Options),
	) (*lambda.RemovePermissionOutput, error)
}

// Clients are the two APIs the section calls.
type Clients struct {
	Lambda  Lambda
	History History
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
		g.Get("/", m.functions)
		g.Get("/function", m.function)
		g.Post("/function/invoke", m.invoke)
		g.Post("/function/policy", m.putPolicy)
		g.Post("/function/policy/delete", m.deletePolicy)
		g.Post("/function/permission/remove", m.removePermission)
		g.Get("/invocations", m.invocations)
		g.Get("/invocation", m.invocation)
		g.Get("/mappings", m.mappings)
		g.Post("/mappings/state", m.mappingState)
	})
	return nil
}

// Close releases nothing; the module holds no resources of its own.
func (m *Module) Close(context.Context) error { return nil }

func (m *Module) clients(c gas.Context) Clients {
	return m.newClients(web.FromContext(c).Credentials())
}

func functionLink(name string) string {
	return web.Link(Path+"/function", "name", name)
}

// Function is a function's configuration.
type Function struct {
	Modified     string
	Name         string
	ARN          string
	State        string
	StateReason  string
	UpdateStatus string
	UpdateReason string
	PackageType  string
	ImageURI     string
	Role         string
	Description  string
	Link         string
	Architecture string
	Environment  []Pair
	Memory       int32
	Timeout      int32
}

// Pair is a name and a value.
type Pair struct {
	Name  string
	Value string
}

func toFunction(f *types.FunctionConfiguration) Function {
	name := aws.ToString(f.FunctionName)
	out := Function{
		Name:         name,
		ARN:          aws.ToString(f.FunctionArn),
		State:        string(f.State),
		StateReason:  aws.ToString(f.StateReason),
		UpdateStatus: string(f.LastUpdateStatus),
		UpdateReason: aws.ToString(f.LastUpdateStatusReason),
		PackageType:  string(f.PackageType),
		Role:         aws.ToString(f.Role),
		Description:  aws.ToString(f.Description),
		Modified:     aws.ToString(f.LastModified),
		Memory:       aws.ToInt32(f.MemorySize),
		Timeout:      aws.ToInt32(f.Timeout),
		Link:         functionLink(name),
	}
	archs := make([]string, len(f.Architectures))
	for i, a := range f.Architectures {
		archs[i] = string(a)
	}
	out.Architecture = strings.Join(archs, ", ")
	if f.Environment != nil {
		for k, v := range f.Environment.Variables {
			out.Environment = append(out.Environment, Pair{Name: k, Value: v})
		}
		sort.Slice(
			out.Environment,
			func(i, j int) bool { return out.Environment[i].Name < out.Environment[j].Name },
		)
	}
	return out
}

type functionsView struct {
	NextLink  string
	FirstLink string
	Functions []Function
}

func (m *Module) functions(c gas.Context) error {
	marker := c.Query("marker")
	in := &lambda.ListFunctionsInput{MaxItems: aws.Int32(pageSize)}
	if marker != "" {
		in.Marker = aws.String(marker)
	}
	out, err := m.clients(c).Lambda.ListFunctions(c, in)
	if err != nil {
		return m.render.Fail(c, Key, "Functions", err)
	}
	v := functionsView{}
	for i := range out.Functions {
		v.Functions = append(v.Functions, toFunction(&out.Functions[i]))
	}
	if next := aws.ToString(out.NextMarker); next != "" {
		v.NextLink = web.Link(Path, "marker", next)
	}
	if marker != "" {
		v.FirstLink = Path
	}
	return m.render.Render(
		c,
		web.Page{Name: "functions/functions", Title: "Functions", Section: Key, Data: v},
	)
}

// Mapping is an event source mapping.
type Mapping struct {
	Modified     time.Time
	UUID         string
	Source       string
	Function     string
	FunctionLink string
	State        string
	Reason       string
	LastResult   string
	BatchSize    int32
	Enabled      bool
}

func toMapping(e *types.EventSourceMappingConfiguration) Mapping {
	fn := aws.ToString(e.FunctionArn)
	name := fn
	if i := strings.LastIndexByte(fn, ':'); i >= 0 {
		name = fn[i+1:]
	}
	state := aws.ToString(e.State)
	return Mapping{
		UUID:         aws.ToString(e.UUID),
		Source:       aws.ToString(e.EventSourceArn),
		Function:     name,
		FunctionLink: functionLink(name),
		State:        state,
		Reason:       aws.ToString(e.StateTransitionReason),
		LastResult:   aws.ToString(e.LastProcessingResult),
		BatchSize:    aws.ToInt32(e.BatchSize),
		Modified:     aws.ToTime(e.LastModified),
		Enabled:      state == "Enabled" || state == "Enabling",
	}
}

// Result is the outcome of an invocation run from the console.
type Result struct {
	Error   string
	Payload string
	Log     string
	Status  int32
}

type functionView struct {
	Result      *Result
	Policy      *web.Policy
	Payload     string
	HistoryErr  string
	HistoryLink string
	Invocations []Row
	Mappings    []Mapping
	Function
}

func (m *Module) load(c gas.Context, name string) (functionView, error) {
	cl := m.clients(c)
	out, err := cl.Lambda.GetFunction(c, &lambda.GetFunctionInput{FunctionName: aws.String(name)})
	if err != nil {
		return functionView{}, err
	}
	if out.Configuration == nil {
		return functionView{}, &web.MissingField{
			Operation: "GetFunction",
			Field:     "its Configuration",
		}
	}
	v := functionView{Function: toFunction(out.Configuration), Payload: "{}"}
	if out.Code != nil {
		v.ImageURI = aws.ToString(out.Code.ImageUri)
	}
	maps, err := cl.Lambda.ListEventSourceMappings(c, &lambda.ListEventSourceMappingsInput{
		FunctionName: aws.String(name),
	})
	if err != nil {
		return functionView{}, err
	}
	for i := range maps.EventSourceMappings {
		v.Mappings = append(v.Mappings, toMapping(&maps.EventSourceMappings[i]))
	}
	v.Policy = loadPolicy(c, cl.Lambda, name, v.ARN)
	v.HistoryLink = web.Link(Path+"/invocations", "function", name)
	// The history is the service's own API; the page stands without it.
	p, err := cl.History.Invocations(
		c,
		url.Values{"function": {name}, "limit": {strconv.Itoa(recent)}},
	)
	if err != nil {
		v.HistoryErr = web.Describe(err).Message
	} else {
		v.Invocations = rows(p.Items)
	}
	return v, nil
}

func (m *Module) function(c gas.Context) error {
	name := c.Query("name")
	v, err := m.load(c, name)
	if err != nil {
		return m.render.Fail(c, Key, name, err)
	}
	return m.render.Render(
		c,
		web.Page{Name: "functions/function", Title: name, Section: Key, Data: v},
	)
}

// invoke runs the function synchronously with the posted payload and the
// tail of its log, and answers the result block to an HTMX request, or the
// function's page with the result to a plain form post.
func (m *Module) invoke(c gas.Context) error {
	form := c.Request().PostForm
	name := form.Get("name")
	payload := strings.TrimSpace(form.Get("payload"))
	if payload == "" {
		payload = "{}"
	}
	res := m.run(c, name, payload)

	var v functionView
	if web.IsHTMX(c.Request()) {
		v = functionView{Function: Function{Name: name}}
	} else {
		var err error
		if v, err = m.load(c, name); err != nil {
			return m.render.Fail(c, Key, name, err)
		}
	}
	v.Payload, v.Result = payload, res
	return m.render.Render(c, web.Page{
		Name: "functions/function", Title: name, Section: Key, Data: v, Block: "result",
	})
}

// run invokes the function with payload and returns the outcome: the
// function's result, error and log tail, or why it did not run.
func (m *Module) run(c gas.Context, name, payload string) *Result {
	if !json.Valid([]byte(payload)) {
		return &Result{Error: "The payload is not valid JSON."}
	}
	out, err := m.clients(c).Lambda.Invoke(c, &lambda.InvokeInput{
		FunctionName:   aws.String(name),
		InvocationType: types.InvocationTypeRequestResponse,
		LogType:        types.LogTypeTail,
		Payload:        []byte(payload),
	})
	if err != nil {
		return &Result{Error: web.Describe(err).Message}
	}
	res := &Result{Status: out.StatusCode, Payload: Pretty(out.Payload)}
	if fe := aws.ToString(out.FunctionError); fe != "" {
		res.Error = "The function failed (" + fe + ")."
	}
	if lr := aws.ToString(out.LogResult); lr != "" {
		b, derr := base64.StdEncoding.DecodeString(lr)
		if derr != nil {
			res.Log = "The service sent a log tail that is not base64: " + derr.Error()
		} else {
			res.Log = string(b)
		}
	}
	return res
}

// Pretty returns raw JSON indented, a JSON string as its text (indented
// when the text is JSON itself, as the history gives a payload), null or
// nothing as "", and anything else as it is.
func Pretty(raw []byte) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var s string
	if raw[0] == '"' && json.Unmarshal(raw, &s) == nil {
		if inner := []byte(
			strings.TrimSpace(s),
		); len(inner) > 0 &&
			(inner[0] == '{' || inner[0] == '[') {
			var buf bytes.Buffer
			if json.Indent(&buf, inner, "", "  ") == nil {
				return buf.String()
			}
		}
		return s
	}
	var buf bytes.Buffer
	if json.Indent(&buf, raw, "", "  ") == nil {
		return buf.String()
	}
	return string(raw)
}

// milliseconds formats the history's duration, a number of milliseconds,
// and shows anything else as Pretty does.
func milliseconds(raw json.RawMessage) string {
	var ms float64
	if json.Unmarshal(raw, &ms) == nil {
		return strconv.FormatFloat(ms, 'f', -1, 64) + " ms"
	}
	return Pretty(raw)
}

// Row is an invocation in a list.
type Row struct {
	At       time.Time
	Link     string
	Duration string
	Invocation
}

func rows(items []Invocation) []Row {
	out := make([]Row, 0, len(items))
	for _, inv := range items {
		at, _ := time.Parse(time.RFC3339Nano, inv.Time)
		out = append(out, Row{
			Invocation: inv,
			At:         at,
			Link:       web.Link(Path+"/invocation", "id", inv.RequestID),
			Duration:   milliseconds(inv.Duration),
		})
	}
	return out
}

var invocationFilters = []string{"function", "status", "source", "since", "until"}

type invocationsView struct {
	Function  string
	Status    string
	Source    string
	Since     string
	Until     string
	NextLink  string
	FirstLink string
	Rows      []Row
}

func (m *Module) invocations(c gas.Context) error {
	q := c.Request().URL.Query()
	query := url.Values{"limit": {strconv.Itoa(pageSize)}}
	kv := make([]string, 0, 2*len(invocationFilters))
	for _, f := range invocationFilters {
		val := strings.TrimSpace(q.Get(f))
		kv = append(kv, f, val)
		if val == "" {
			continue
		}
		if f == "since" || f == "until" {
			val = toRFC3339(val)
		}
		query.Set(f, val)
	}
	if cur := q.Get("cursor"); cur != "" {
		query.Set("cursor", cur)
	}
	p, err := m.clients(c).History.Invocations(c, query)
	if err != nil {
		return m.render.Fail(c, Key, "Invocations", err)
	}
	v := invocationsView{
		Function: q.Get("function"), Status: q.Get("status"), Source: q.Get("source"),
		Since: q.Get("since"), Until: q.Get("until"), Rows: rows(p.Items),
	}
	if p.NextCursor != "" {
		v.NextLink = web.Link(Path+"/invocations", append(kv, "cursor", p.NextCursor)...)
	}
	if q.Get("cursor") != "" {
		v.FirstLink = web.Link(Path+"/invocations", kv...)
	}
	return m.render.Render(c, web.Page{
		Name:    "functions/invocations",
		Title:   "Invocations",
		Section: Key,
		Data:    v,
		Block:   "results",
	})
}

// toRFC3339 turns the value of a datetime-local input, read as UTC, into
// RFC 3339, and leaves any other value to the service to judge.
func toRFC3339(v string) string {
	for _, layout := range []string{"2006-01-02T15:04", "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, v); err == nil {
			return t.UTC().Format(time.RFC3339)
		}
	}
	return v
}

type invocationView struct {
	FunctionLink string
	Payload      string
	Result       string
	Row
}

func (m *Module) invocation(c gas.Context) error {
	id := c.Query("id")
	inv, err := m.clients(c).History.Invocation(c, id)
	if err != nil {
		return m.render.Fail(c, Key, "Invocation", err)
	}
	r := rows([]Invocation{inv})[0]
	v := invocationView{
		Row:          r,
		FunctionLink: functionLink(inv.Function),
		Payload:      Pretty(inv.Payload),
		Result:       Pretty(inv.Result),
	}
	return m.render.Render(
		c,
		web.Page{Name: "functions/invocation", Title: "Invocation " + id, Section: Key, Data: v},
	)
}

type mappingsView struct {
	Mappings []Mapping
}

func (m *Module) mappings(c gas.Context) error {
	api := m.clients(c).Lambda
	in := &lambda.ListEventSourceMappingsInput{MaxItems: aws.Int32(100)}
	v := mappingsView{}
	for {
		out, err := api.ListEventSourceMappings(c, in)
		if err != nil {
			return m.render.Fail(c, Key, "Event source mappings", err)
		}
		for i := range out.EventSourceMappings {
			v.Mappings = append(v.Mappings, toMapping(&out.EventSourceMappings[i]))
		}
		if aws.ToString(out.NextMarker) == "" {
			break
		}
		in.Marker = out.NextMarker
	}
	return m.render.Render(
		c,
		web.Page{Name: "functions/mappings", Title: "Event source mappings", Section: Key, Data: v},
	)
}

func (m *Module) mappingState(c gas.Context) error {
	form := c.Request().PostForm
	id := form.Get("uuid")
	back := Path + "/mappings"
	if fn := form.Get("function"); fn != "" {
		back = functionLink(fn)
	}
	enable := form.Get("enabled") == "true"
	_, err := m.clients(c).Lambda.UpdateEventSourceMapping(c, &lambda.UpdateEventSourceMappingInput{
		UUID:    aws.String(id),
		Enabled: aws.Bool(enable),
	})
	if err != nil {
		return web.Failed(c, back, "Mapping "+id+" was not changed", err)
	}
	word := "Disabled"
	if enable {
		word = "Enabled"
	}
	return web.Done(c, back, word+" mapping "+id+".")
}
