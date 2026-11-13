package signin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"tule.dev/console/internal/awsclient"
	"tule.dev/console/internal/session"
)

// ErrRefused is returned when the service refused the key: it answered 401
// or 403, as every Tule service answers an unknown key or a bad signature.
var ErrRefused = errors.New("the key was refused")

// UnverifiedError is a key the service could not be asked about: it did
// not answer, or answered with a fault of its own. Err holds the detail,
// endpoints included, for the log; Message is what a signed-out visitor
// may see.
type UnverifiedError struct {
	Err     error
	Service string
}

func (e *UnverifiedError) Error() string {
	return e.Service + " could not verify the key: " + e.Err.Error()
}

func (e *UnverifiedError) Unwrap() error { return e.Err }

// Message says which service could not verify the key and how, without the
// endpoint or the SDK's text.
func (e *UnverifiedError) Message() string {
	var send *smithyhttp.RequestSendError
	var re *awshttp.ResponseError
	if !errors.As(e.Err, &send) && !errors.Is(e.Err, context.DeadlineExceeded) &&
		errors.As(e.Err, &re) && re.Response != nil {
		return "The key could not be verified: " + e.Service + " answered with an error. Try again shortly."
	}
	return "The key could not be verified: " + e.Service + " is unreachable. Try again shortly."
}

// verifyTimeout bounds the call that checks a key.
const verifyTimeout = 15 * time.Second

// Verifier checks a key by making a signed call with it, and returns who
// the key is. It returns an error wrapping ErrRefused for a key the
// service refused, and any other error when the service could not be
// asked.
type Verifier func(ctx context.Context, creds aws.Credentials) (session.Principal, error)

// Endpoints are the configured services a key can be checked against,
// nil for one that is not configured.
type Endpoints struct {
	Identity    *awsclient.Endpoint
	ObjectStore *awsclient.Endpoint
	SecretStore *awsclient.Endpoint
	Accounts    *awsclient.Endpoint
	Mailbox     *awsclient.Endpoint
	Queues      *awsclient.Endpoint
	Functions   *awsclient.Endpoint
}

// check is a signed call that succeeds only for a key the service accepts.
type check struct {
	call    func(ctx context.Context, creds aws.Credentials) (session.Principal, error)
	service string
}

// NewVerifier returns the verifier of the configured services: identity's
// GetCallerIdentity when identity is configured, which also names the
// principal and which every principal may call; else the cheapest read of
// the first configured service, in the order the console lists them. A
// read the service denies by policy still verifies the key, and names its
// principal, so a key without permissions signs in and is shown what it
// may not do.
func NewVerifier(e Endpoints) (Verifier, error) {
	c, ok := firstCheck(e)
	if !ok {
		return nil, errors.New("signin: no service to verify keys against")
	}
	return func(ctx context.Context, creds aws.Credentials) (session.Principal, error) {
		ctx, cancel := context.WithTimeout(ctx, verifyTimeout)
		defer cancel()
		p, err := c.call(ctx, creds)
		if arn, ok := deniedByPolicy(err); ok && c.service != "identity" {
			// The service verified the key and then found no policy that
			// allows the read: the key is good, and its principal may
			// still be allowed elsewhere, or be shown that it is not.
			p, err = session.Principal{ARN: arn}, nil
		}
		if err != nil {
			if refused(err) {
				return session.Principal{}, fmt.Errorf("%s: %w", c.service, ErrRefused)
			}
			return session.Principal{}, &UnverifiedError{Service: c.service, Err: err}
		}
		p.KeyHint = keyHint(creds.AccessKeyID)
		return p, nil
	}, nil
}

// call is a signed read of one service with a key.
type call func(ctx context.Context, ep awsclient.Endpoint, creds aws.Credentials) (session.Principal, error)

// firstCheck returns the check of the first configured service, in the
// console's order with identity first.
func firstCheck(e Endpoints) (check, bool) {
	for _, c := range []struct {
		ep      *awsclient.Endpoint
		call    call
		service string
	}{
		{e.Identity, callerIdentity, "identity"},
		{e.ObjectStore, listBuckets, "object-store"},
		{e.SecretStore, listSecrets, "secret-store"},
		{e.Accounts, describeOrganization, "accounts"},
		{e.Mailbox, getAccount, "mailbox"},
		{e.Queues, listQueues, "queues"},
		{e.Functions, listFunctions, "functions"},
	} {
		if c.ep == nil {
			continue
		}
		ep, fn := *c.ep, c.call
		return check{
			service: c.service,
			call: func(ctx context.Context, creds aws.Credentials) (session.Principal, error) {
				return fn(ctx, ep, creds)
			},
		}, true
	}
	return check{}, false
}

func callerIdentity(
	ctx context.Context,
	ep awsclient.Endpoint,
	creds aws.Credentials,
) (session.Principal, error) {
	out, err := awsclient.STS(ep, creds).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return session.Principal{}, fmt.Errorf("GetCallerIdentity: %w", err)
	}
	return session.Principal{ARN: aws.ToString(out.Arn), Account: aws.ToString(out.Account)}, nil
}

func listBuckets(
	ctx context.Context,
	ep awsclient.Endpoint,
	creds aws.Credentials,
) (session.Principal, error) {
	if _, err := awsclient.S3(ep, creds).ListBuckets(ctx, &s3.ListBucketsInput{}); err != nil {
		return session.Principal{}, fmt.Errorf("ListBuckets: %w", err)
	}
	return session.Principal{}, nil
}

func listSecrets(
	ctx context.Context,
	ep awsclient.Endpoint,
	creds aws.Credentials,
) (session.Principal, error) {
	_, err := awsclient.SecretsManager(ep, creds).ListSecrets(ctx,
		&secretsmanager.ListSecretsInput{MaxResults: aws.Int32(1)})
	if err != nil {
		return session.Principal{}, fmt.Errorf("ListSecrets: %w", err)
	}
	return session.Principal{}, nil
}

// describeOrganization accepts AWSOrganizationsNotInUseException too: a
// service without an organization answers it past the signature check, so
// the key was accepted.
func describeOrganization(
	ctx context.Context,
	ep awsclient.Endpoint,
	creds aws.Credentials,
) (session.Principal, error) {
	_, err := awsclient.Organizations(ep, creds).DescribeOrganization(ctx,
		&organizations.DescribeOrganizationInput{})
	var notInUse *orgtypes.AWSOrganizationsNotInUseException
	if err != nil && !errors.As(err, &notInUse) {
		return session.Principal{}, fmt.Errorf("DescribeOrganization: %w", err)
	}
	return session.Principal{}, nil
}

func getAccount(
	ctx context.Context,
	ep awsclient.Endpoint,
	creds aws.Credentials,
) (session.Principal, error) {
	if _, err := awsclient.SESv2(ep, creds).GetAccount(ctx, &sesv2.GetAccountInput{}); err != nil {
		return session.Principal{}, fmt.Errorf("GetAccount: %w", err)
	}
	return session.Principal{}, nil
}

func listQueues(
	ctx context.Context,
	ep awsclient.Endpoint,
	creds aws.Credentials,
) (session.Principal, error) {
	_, err := awsclient.SQS(ep, creds).
		ListQueues(ctx, &sqs.ListQueuesInput{MaxResults: aws.Int32(1)})
	if err != nil {
		return session.Principal{}, fmt.Errorf("ListQueues: %w", err)
	}
	return session.Principal{}, nil
}

func listFunctions(
	ctx context.Context,
	ep awsclient.Endpoint,
	creds aws.Credentials,
) (session.Principal, error) {
	_, err := awsclient.Lambda(ep, creds).
		ListFunctions(ctx, &lambda.ListFunctionsInput{MaxItems: aws.Int32(1)})
	if err != nil {
		return session.Principal{}, fmt.Errorf("ListFunctions: %w", err)
	}
	return session.Principal{}, nil
}

// deniedByPolicy reports whether err is a service's AccessDenied for a
// request no policy allows, and returns the principal the denial names.
// Every Tule service answers it, as AWS does, only past the signature
// check, in IAM's form: "User: <arn> is not authorized to perform: ...".
// A bare AccessDenied is not one: object-store answers some malformed
// signatures with it.
func deniedByPolicy(err error) (string, bool) {
	var apiErr smithy.APIError
	if err == nil || !errors.As(err, &apiErr) {
		return "", false
	}
	if code := apiErr.ErrorCode(); code != "AccessDenied" && code != "AccessDeniedException" {
		return "", false
	}
	rest, ok := strings.CutPrefix(apiErr.ErrorMessage(), "User: ")
	if !ok {
		return "", false
	}
	arn, _, ok := strings.Cut(rest, " is not authorized to perform: ")
	if !ok || !strings.HasPrefix(arn, "arn:") {
		return "", false
	}
	return arn, true
}

// refused reports whether err is the service refusing the key.
func refused(err error) bool {
	var re *awshttp.ResponseError
	if errors.As(err, &re) {
		s := re.HTTPStatusCode()
		return s == http.StatusUnauthorized || s == http.StatusForbidden
	}
	return false
}

// keyHint is the last four characters of an access key ID of AWS's
// length, at least 16, and "" for a shorter one, whose last four
// characters would be most or all of it.
func keyHint(id string) string {
	if len(id) < 16 {
		return ""
	}
	return id[len(id)-4:]
}
