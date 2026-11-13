package functions_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/smithy-go"

	"tule.dev/console/internal/app"
	"tule.dev/console/internal/awsclient"
	"tule.dev/console/internal/consoletest"
	"tule.dev/console/internal/modules/functions"
)

// fakeLambda is Lambda's functions and mappings in memory, and the
// functions retrieval API, served over HTTP.
type fakeLambda struct {
	fns      map[string]types.FunctionConfiguration
	mappings map[string]*types.EventSourceMappingConfiguration
	invoked  []*lambda.InvokeInput
	history  []functions.Invocation
	queries  []url.Values
	mu       sync.Mutex
}

func newFake() *fakeLambda {
	return &fakeLambda{
		fns:      map[string]types.FunctionConfiguration{},
		mappings: map[string]*types.EventSourceMappingConfiguration{},
	}
}

func (f *fakeLambda) add(name string) {
	f.fns[name] = types.FunctionConfiguration{
		FunctionName: aws.String(
			name,
		),
		FunctionArn:      aws.String("arn:aws:lambda:us-east-1:000000000000:function:" + name),
		State:            types.StateActive,
		LastUpdateStatus: types.LastUpdateStatusSuccessful,
		PackageType:      types.PackageTypeImage,
		MemorySize: aws.Int32(
			128,
		),
		Timeout:       aws.Int32(3),
		Architectures: []types.Architecture{types.ArchitectureArm64},
		Environment:   &types.EnvironmentResponse{Variables: map[string]string{"STAGE": "dev"}},
	}
}

func (f *fakeLambda) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.Contains(r.Header.Get("Authorization"), "/lambda/aws4_request") {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path == "/_functions/invocations" {
		f.queries = append(f.queries, r.URL.Query())
		_ = json.NewEncoder(w).Encode(functions.InvocationPage{Items: f.history})
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/_functions/invocations/")
	for _, inv := range f.history {
		if inv.RequestID == id {
			_ = json.NewEncoder(w).Encode(inv)
			return
		}
	}
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write(
		[]byte(
			`{"code":"ResourceNotFoundException","message":"No invocation has that request ID."}`,
		),
	)
}

func (f *fakeLambda) ListFunctions(
	context.Context, *lambda.ListFunctionsInput, ...func(*lambda.Options),
) (*lambda.ListFunctionsOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := &lambda.ListFunctionsOutput{}
	for _, fn := range f.fns {
		out.Functions = append(out.Functions, fn)
	}
	return out, nil
}

func (f *fakeLambda) GetFunction(
	_ context.Context, in *lambda.GetFunctionInput, _ ...func(*lambda.Options),
) (*lambda.GetFunctionOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn, ok := f.fns[*in.FunctionName]
	if !ok {
		return nil, &smithy.GenericAPIError{
			Code:    "ResourceNotFoundException",
			Message: "Function not found: " + *in.FunctionName,
		}
	}
	return &lambda.GetFunctionOutput{
		Configuration: &fn, Code: &types.FunctionCodeLocation{ImageUri: aws.String("echo:latest")},
	}, nil
}

func (f *fakeLambda) Invoke(
	_ context.Context,
	in *lambda.InvokeInput,
	_ ...func(*lambda.Options),
) (*lambda.InvokeOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.invoked = append(f.invoked, in)
	log := base64.StdEncoding.EncodeToString(
		[]byte("START RequestId: r-1\n<script>log</script>\nEND RequestId: r-1\n"),
	)
	out := &lambda.InvokeOutput{StatusCode: 200, Payload: in.Payload, LogResult: aws.String(log)}
	if strings.Contains(string(in.Payload), "fail") {
		out.FunctionError = aws.String("Unhandled")
		out.Payload = []byte(`{"errorMessage":"boom","errorType":"Error"}`)
	}
	return out, nil
}

func (f *fakeLambda) ListEventSourceMappings(
	_ context.Context, in *lambda.ListEventSourceMappingsInput, _ ...func(*lambda.Options),
) (*lambda.ListEventSourceMappingsOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := &lambda.ListEventSourceMappingsOutput{}
	for _, m := range f.mappings {
		if in.FunctionName == nil || strings.HasSuffix(*m.FunctionArn, ":"+*in.FunctionName) {
			out.EventSourceMappings = append(out.EventSourceMappings, *m)
		}
	}
	return out, nil
}

func (f *fakeLambda) UpdateEventSourceMapping(
	_ context.Context, in *lambda.UpdateEventSourceMappingInput, _ ...func(*lambda.Options),
) (*lambda.UpdateEventSourceMappingOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := f.mappings[*in.UUID]
	if *in.Enabled {
		m.State = aws.String("Enabled")
	} else {
		m.State = aws.String("Disabled")
	}
	return &lambda.UpdateEventSourceMappingOutput{}, nil
}

func start(t *testing.T, f *fakeLambda) *consoletest.Browser {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	ep := awsclient.Endpoint{URL: srv.URL, Region: "us-east-1", HTTP: srv.Client()}
	s := consoletest.Start(t, app.Overrides{Functions: func(c aws.Credentials) functions.Clients {
		return functions.Clients{Lambda: f, History: functions.NewRetrieval(ep, c)}
	}}, nil, "lambda")
	b := s.Browser(t)
	b.SignIn(consoletest.KeyID, consoletest.Secret)
	return b
}

func withMapping(f *fakeLambda) {
	f.mappings["uuid-1"] = &types.EventSourceMappingConfiguration{
		UUID: aws.String(
			"uuid-1",
		),
		EventSourceArn: aws.String("arn:aws:sqs:us-east-1:000000000000:orders"),
		FunctionArn:    aws.String("arn:aws:lambda:us-east-1:000000000000:function:echo"),
		State:          aws.String("Enabled"),
		BatchSize:      aws.Int32(10),
	}
}

func TestFunctionsAndDetails(t *testing.T) {
	f := newFake()
	f.add("echo")
	withMapping(f)
	f.history = []functions.Invocation{{
		RequestID: "r-1", Function: "echo", Time: "2026-11-13T10:00:00.000Z", Source: "invoke",
		Status: "succeeded", Duration: json.RawMessage(`12.5`),
	}}
	b := start(t, f)

	res := b.Get("/lambda")
	consoletest.RequireStatus(t, res, http.StatusOK)
	consoletest.RequireText(t, res, "echo", "Active", "Image", "128 MB", "3 s")

	res = b.Get("/lambda/function?name=echo")
	consoletest.RequireStatus(t, res, http.StatusOK)
	consoletest.RequireText(
		t,
		res,
		"echo:latest",
		"arm64",
		"STAGE",
		"orders",
		"Enabled",
		"r-1",
		"succeeded",
		"12.5",
	)
	if q := f.queries[0]; q.Get("function") != "echo" {
		t.Fatalf("history asked %v", q)
	}

	res = b.Get("/lambda/function?name=nope")
	consoletest.RequireText(t, res, "Function not found")
}

func TestHistoryDownDoesNotBreakTheFunction(t *testing.T) {
	f := newFake()
	f.add("echo")
	s := consoletest.Start(t, app.Overrides{Functions: func(c aws.Credentials) functions.Clients {
		ep := awsclient.Endpoint{
			URL:    "http://127.0.0.1:1",
			Region: "us-east-1",
			HTTP:   http.DefaultClient,
		}
		return functions.Clients{Lambda: f, History: functions.NewRetrieval(ep, c)}
	}}, nil, "lambda")
	b := s.Browser(t)
	b.SignIn(consoletest.KeyID, consoletest.Secret)
	res := b.Get("/lambda/function?name=echo")
	consoletest.RequireStatus(t, res, http.StatusOK)
	consoletest.RequireText(t, res, "The invocation history could not be read")
}

func TestInvoke(t *testing.T) {
	f := newFake()
	f.add("echo")
	b := start(t, f)
	b.Get("/lambda/function?name=echo")

	res := b.PostForm(
		"/lambda/function/invoke",
		url.Values{"name": {"echo"}, "payload": {`{"hello":"world"}`}},
	)
	consoletest.RequireStatus(t, res, http.StatusOK)
	consoletest.RequireText(
		t,
		res,
		`"hello": "world"`,
		"START RequestId: r-1",
		"<script>log</script>",
		"Status 200",
	)
	consoletest.RequireInert(t, res)
	in := f.invoked[0]
	if in.InvocationType != types.InvocationTypeRequestResponse || in.LogType != types.LogTypeTail {
		t.Fatalf("invoked %+v", in)
	}

	res = b.HTMXPost(
		"/lambda/function/invoke",
		url.Values{"name": {"echo"}, "payload": {`{"fail":true}`}},
	)
	consoletest.RequireStatus(t, res, http.StatusOK)
	if strings.Contains(string(res.Body), "<h1") {
		t.Fatal("the HTMX invoke answered more than the result")
	}
	consoletest.RequireText(t, res, "The function failed (Unhandled).", "boom")

	n := len(f.invoked)
	res = b.PostForm(
		"/lambda/function/invoke",
		url.Values{"name": {"echo"}, "payload": {`{not json`}},
	)
	consoletest.RequireText(t, res, "The payload is not valid JSON.")
	if len(f.invoked) != n {
		t.Fatal("an invalid payload was sent")
	}
}

func TestInvocationHistory(t *testing.T) {
	f := newFake()
	f.add("echo")
	f.history = []functions.Invocation{
		{
			RequestID:    "r-9",
			Function:     "echo",
			Time:         "2026-11-13T10:00:00.000Z",
			Source:       "eventSourceMapping",
			Status:       "failed",
			ErrorType:    "Runtime.ExitError",
			ErrorMessage: "exit status 2",
			Payload: json.RawMessage(
				`{"Records":[]}`,
			),
			Result: json.RawMessage(`"plain text result"`),
			Log:    "line one\nline two",
		},
	}
	b := start(t, f)

	res := b.Get(
		"/lambda/invocations?function=echo&status=failed&source=eventSourceMapping&since=2026-11-13T09%3A00",
	)
	consoletest.RequireStatus(t, res, http.StatusOK)
	consoletest.RequireText(t, res, "r-9", "failed", "Runtime.ExitError")
	q := f.queries[len(f.queries)-1]
	if q.Get("function") != "echo" || q.Get("status") != "failed" ||
		q.Get("source") != "eventSourceMapping" ||
		q.Get("since") != "2026-11-13T09:00:00Z" {
		t.Fatalf("history asked %v", q)
	}

	res = b.Get("/lambda/invocation?id=r-9")
	consoletest.RequireStatus(t, res, http.StatusOK)
	consoletest.RequireText(
		t,
		res,
		`"Records": []`,
		"plain text result",
		"line one line two",
		"exit status 2",
	)

	res = b.Get("/lambda/invocation?id=missing")
	consoletest.RequireStatus(t, res, http.StatusNotFound)
}

func TestMappingState(t *testing.T) {
	f := newFake()
	f.add("echo")
	withMapping(f)
	b := start(t, f)
	res := b.Get("/lambda/mappings")
	consoletest.RequireText(t, res, "orders", "Enabled", "Disable")

	res = b.PostForm("/lambda/mappings/state", url.Values{"uuid": {"uuid-1"}, "enabled": {"false"}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Disabled mapping uuid-1.")
	if *f.mappings["uuid-1"].State != "Disabled" {
		t.Fatal("the mapping is still enabled")
	}
	res = b.PostForm(
		"/lambda/mappings/state",
		url.Values{"uuid": {"uuid-1"}, "enabled": {"true"}, "function": {"echo"}},
	)
	if res.Location() != "/lambda/function?name=echo" {
		t.Fatalf("back to %q", res.Location())
	}
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Enabled mapping uuid-1.")
}

func TestHostileFunctionsRenderInert(t *testing.T) {
	f := newFake()
	h := consoletest.HostileName
	f.add("x")
	fn := f.fns["x"]
	fn.Description, fn.StateReason, fn.Role = aws.String(h), aws.String(h), aws.String(h)
	fn.Environment = &types.EnvironmentResponse{Variables: map[string]string{h: h}}
	f.fns["x"] = fn
	f.history = []functions.Invocation{{
		RequestID: "r", Function: h, Time: h, Source: h, Status: h, ErrorType: h, ErrorMessage: h,
		Payload: json.RawMessage(`"` + strings.ReplaceAll(h, `"`, `\"`) + `"`), Log: h,
	}}
	b := start(t, f)
	for _, path := range []string{"/lambda", "/lambda/function?name=x", "/lambda/invocations", "/lambda/invocation?id=r"} {
		res := b.Get(path)
		consoletest.RequireStatus(t, res, http.StatusOK)
		consoletest.RequireInert(t, res)
	}
}

func TestPretty(t *testing.T) {
	for in, want := range map[string]string{
		``:            ``,
		`null`:        ``,
		`{"a":1}`:     "{\n  \"a\": 1\n}",
		`"text"`:      `text`,
		`not json {`:  `not json {`,
		`  [1, 2]  `:  "[\n  1,\n  2\n]",
		`12.5`:        `12.5`,
		`"a\"b<tag>"`: `a"b<tag>`,
		`"{\"a\":1}"`: "{\n  \"a\": 1\n}",
	} {
		if got := functions.Pretty([]byte(in)); got != want {
			t.Errorf("Pretty(%q) = %q, want %q", in, got, want)
		}
	}
}

// hollowLambda answers GetFunction without its Configuration.
type hollowLambda struct{ *fakeLambda }

func (hollowLambda) GetFunction(
	context.Context, *lambda.GetFunctionInput, ...func(*lambda.Options),
) (*lambda.GetFunctionOutput, error) {
	return &lambda.GetFunctionOutput{}, nil
}

func TestHollowAnswersAreErrors(t *testing.T) {
	f := newFake()
	s := consoletest.Start(t, app.Overrides{Functions: func(aws.Credentials) functions.Clients {
		return functions.Clients{Lambda: hollowLambda{f}}
	}}, nil, "lambda")
	b := s.Browser(t)
	b.SignIn(consoletest.KeyID, consoletest.Secret)
	res := b.Get("/lambda/function?name=x")
	consoletest.RequireStatus(t, res, http.StatusBadGateway)
	consoletest.RequireText(t, res, "GetFunction without its Configuration")
}
