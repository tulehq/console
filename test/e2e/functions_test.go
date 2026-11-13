//go:build e2e

package e2e

import (
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"tule.dev/console/internal/awsclient"
	"tule.dev/console/internal/consoletest"
	"tule.dev/console/internal/modules/functions"
)

// executionRole is the role the echo functions run with: it trusts Lambda,
// and may poll a queue, as a mapping's role must. It is created once, the
// first time a test asks for it.
var executionRole struct {
	err  error
	arn  string
	once sync.Once
}

// lambdaRole returns the execution role's ARN, creating the role in
// identity with the root key the first time.
func lambdaRole(t *testing.T) string {
	t.Helper()
	executionRole.once.Do(func() {
		ic := awsclient.IAM(endpoint("identity"), rootCreds)
		name := unique("lambda-")
		out, err := ic.CreateRole(t.Context(), &iam.CreateRoleInput{
			RoleName: aws.String(name),
			AssumeRolePolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":[` +
				`{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},` +
				`"Action":"sts:AssumeRole"}]}`),
		})
		if err != nil {
			executionRole.err = err
			return
		}
		_, executionRole.err = ic.PutRolePolicy(t.Context(), &iam.PutRolePolicyInput{
			RoleName:   aws.String(name),
			PolicyName: aws.String("poll"),
			PolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
				`"Action":["sqs:ReceiveMessage","sqs:DeleteMessage","sqs:GetQueueAttributes",` +
				`"sqs:GetQueueUrl"],"Resource":"*"}]}`),
		})
		executionRole.arn = aws.ToString(out.Role.Arn)
	})
	requireNoErr(t, executionRole.err, "create the execution role")
	return executionRole.arn
}

// createEcho creates a function of the echo image and waits until it is
// Active, deleting it when the test ends.
func createEcho(t *testing.T, sdk *lambda.Client, name string) {
	t.Helper()
	_, err := sdk.CreateFunction(t.Context(), &lambda.CreateFunctionInput{
		FunctionName:  aws.String(name),
		PackageType:   types.PackageTypeImage,
		Code:          &types.FunctionCode{ImageUri: aws.String(fn.image)},
		Role:          aws.String(lambdaRole(t)),
		Architectures: []types.Architecture{types.Architecture(hostArch())},
		Environment:   &types.Environment{Variables: map[string]string{"STAGE": "e2e"}},
	})
	requireNoErr(t, err, "create function "+name)
	t.Cleanup(func() {
		_, _ = sdk.DeleteFunction(
			t.Context(),
			&lambda.DeleteFunctionInput{FunctionName: aws.String(name)},
		)
	})
	w := lambda.NewFunctionActiveV2Waiter(sdk, func(o *lambda.FunctionActiveV2WaiterOptions) {
		o.MinDelay, o.MaxDelay = 100*time.Millisecond, time.Second
	})
	err = w.Wait(
		t.Context(),
		&lambda.GetFunctionInput{FunctionName: aws.String(name)},
		clientTimeout,
	)
	requireNoErr(t, err, "wait for "+name+" to be Active")
}

func TestFunctions(t *testing.T) {
	requireFunctions(t)
	sdk := awsclient.Lambda(endpoint("functions"), rootCreds)
	name := unique("echo-")
	createEcho(t, sdk, name)

	b := rootBrowser(t)
	res := b.Get("/lambda")
	consoletest.RequireStatus(t, res, http.StatusOK)
	consoletest.RequireText(t, res, name, "Active", "Image")

	page := b.Get("/lambda/function?name=" + name)
	consoletest.RequireStatus(t, page, http.StatusOK)
	consoletest.RequireText(t, page, fn.image, "STAGE", "e2e", hostArch())

	// Invoke through the console: the result and the log tail come back.
	res = b.PostForm(
		"/lambda/function/invoke",
		url.Values{"name": {name}, "payload": {`{"hello":"world"}`}},
	)
	consoletest.RequireStatus(t, res, http.StatusOK)
	consoletest.RequireText(t, res, `"hello": "world"`, `echo: {"hello":"world"}`, "Status 200")

	// The invocation is in functions' own history, and the console shows it.
	history := functions.NewRetrieval(endpoint("functions"), rootCreds)
	p, err := history.Invocations(t.Context(), url.Values{"function": {name}})
	requireNoErr(t, err, "list invocations")
	if len(p.Items) != 1 || p.Items[0].Status != "succeeded" || p.Items[0].Source != "invoke" {
		t.Fatalf("history %+v", p.Items)
	}
	id := p.Items[0].RequestID
	res = b.Get(
		"/lambda/invocations?" + url.Values{"function": {name}, "status": {"succeeded"}}.Encode(),
	)
	consoletest.RequireText(t, res, id, "succeeded", " ms")
	res = b.Get(
		"/lambda/invocations?" + url.Values{"function": {name}, "status": {"failed"}}.Encode(),
	)
	consoletest.RequireText(t, res, "No invocations.")
	res = b.Get("/lambda/invocation?id=" + id)
	consoletest.RequireStatus(t, res, http.StatusOK)
	consoletest.RequireText(
		t,
		res,
		`"hello": "world"`,
		"START RequestId: "+id,
		"REPORT RequestId: "+id,
	)
	consoletest.RequireInert(t, res)

	res = b.PostForm("/lambda/function/invoke", url.Values{"name": {name}, "payload": {"not json"}})
	consoletest.RequireText(t, res, "The payload is not valid JSON.")
}

func TestEventSourceMappings(t *testing.T) {
	requireFunctions(t)
	sdk := awsclient.Lambda(endpoint("functions"), rootCreds)
	name := unique("consumer-")
	createEcho(t, sdk, name)

	queue := unique("events-")
	q := awsclient.SQS(endpoint("queues"), rootCreds)
	_, err := q.CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String(queue)})
	requireNoErr(t, err, "create queue")
	m, err := sdk.CreateEventSourceMapping(t.Context(), &lambda.CreateEventSourceMappingInput{
		FunctionName:   aws.String(name),
		EventSourceArn: aws.String("arn:aws:sqs:us-east-1:000000000000:" + queue),
		BatchSize:      aws.Int32(5),
	})
	requireNoErr(t, err, "create mapping")
	id := aws.ToString(m.UUID)
	t.Cleanup(func() {
		_, _ = sdk.DeleteEventSourceMapping(
			t.Context(),
			&lambda.DeleteEventSourceMappingInput{UUID: aws.String(id)},
		)
	})

	b := rootBrowser(t)
	res := b.Get("/lambda/mappings")
	consoletest.RequireText(t, res, queue, id, name)

	res = b.PostForm(
		"/lambda/mappings/state",
		url.Values{"uuid": {id}, "enabled": {"false"}, "function": {name}},
	)
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Disabled mapping "+id)
	requireMappingState(t, sdk, id, "Disabled", "Disabling")

	res = b.PostForm("/lambda/mappings/state", url.Values{"uuid": {id}, "enabled": {"true"}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Enabled mapping "+id)
	requireMappingState(t, sdk, id, "Enabled", "Enabling")
}

func requireMappingState(t *testing.T, sdk *lambda.Client, id string, want ...string) {
	t.Helper()
	out, err := sdk.GetEventSourceMapping(
		t.Context(),
		&lambda.GetEventSourceMappingInput{UUID: aws.String(id)},
	)
	requireNoErr(t, err, "get mapping")
	state := aws.ToString(out.State)
	for _, w := range want {
		if strings.EqualFold(state, w) {
			return
		}
	}
	t.Fatalf("mapping state %q, want one of %v", state, want)
}
