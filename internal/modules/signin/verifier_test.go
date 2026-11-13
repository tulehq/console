package signin_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"

	"tule.dev/console/internal/awsclient"
	"tule.dev/console/internal/modules/signin"
)

const callerIdentity = `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
<GetCallerIdentityResult><Arn>arn:aws:iam::000000000000:user/dev</Arn><UserId>AIDAEXAMPLE</UserId>
<Account>000000000000</Account></GetCallerIdentityResult>
<ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></GetCallerIdentityResponse>`

const stsRefusal = `<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><Error><Type>Sender</Type>
<Code>InvalidClientTokenId</Code><Message>The security token included in the request is invalid.</Message></Error>
<RequestId>r</RequestId></ErrorResponse>`

// service answers with status and body, and records what it was asked.
func service(
	t *testing.T,
	status int,
	contentType, body string,
	seen *[]*http.Request,
) awsclient.Endpoint {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*seen = append(*seen, r.Clone(r.Context()))
		w.Header().Set("Content-Type", contentType)
		if strings.HasPrefix(contentType, "application/x-amz-json") {
			w.Header().Set("X-Amzn-ErrorType", "AWSOrganizationsNotInUseException")
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return awsclient.Endpoint{URL: srv.URL, Region: "us-east-1", HTTP: srv.Client()}
}

var key = aws.Credentials{AccessKeyID: "AKIAIOSFODNN7EXAMPLE", SecretAccessKey: "secret"}

func TestVerifierAsksIdentity(t *testing.T) {
	var seen []*http.Request
	id := service(t, 200, "text/xml", callerIdentity, &seen)
	var s3Seen []*http.Request
	s3 := service(t, 200, "application/xml", "<ListAllMyBucketsResult/>", &s3Seen)

	v, err := signin.NewVerifier(signin.Endpoints{Identity: &id, ObjectStore: &s3})
	if err != nil {
		t.Fatal(err)
	}
	p, err := v(t.Context(), key)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if p.ARN != "arn:aws:iam::000000000000:user/dev" || p.Account != "000000000000" ||
		p.KeyHint != "MPLE" {
		t.Fatalf("principal %+v", p)
	}
	if len(seen) != 1 || len(s3Seen) != 0 {
		t.Fatalf(
			"asked identity %d times and object-store %d times, want identity once",
			len(seen),
			len(s3Seen),
		)
	}
	if auth := seen[0].Header.Get(
		"Authorization",
	); !strings.Contains(
		auth,
		"Credential=AKIAIOSFODNN7EXAMPLE/",
	) ||
		!strings.Contains(auth, "/sts/aws4_request") {
		t.Fatalf("the call was not signed with the key for sts: %q", auth)
	}
}

func TestVerifierRefusal(t *testing.T) {
	var seen []*http.Request
	id := service(t, 403, "text/xml", stsRefusal, &seen)
	v, _ := signin.NewVerifier(signin.Endpoints{Identity: &id})
	_, err := v(t.Context(), key)
	if !errors.Is(err, signin.ErrRefused) {
		t.Fatalf("err %v, want ErrRefused", err)
	}
}

func TestVerifierServiceFault(t *testing.T) {
	var seen []*http.Request
	id := service(
		t,
		500,
		"text/xml",
		strings.ReplaceAll(stsRefusal, "InvalidClientTokenId", "InternalFailure"),
		&seen,
	)
	v, _ := signin.NewVerifier(signin.Endpoints{Identity: &id})
	_, err := v(t.Context(), key)
	var uv *signin.UnverifiedError
	if !errors.As(err, &uv) || errors.Is(err, signin.ErrRefused) {
		t.Fatalf("err %v, want an UnverifiedError", err)
	}
	if got := uv.Message(); got != "The key could not be verified: identity answered with an error. Try again shortly." ||
		strings.Contains(got, "127.0.0.1") {
		t.Fatalf("message %q", got)
	}

	down := awsclient.Endpoint{
		URL:    "http://127.0.0.1:1",
		Region: "us-east-1",
		HTTP:   http.DefaultClient,
	}
	v, _ = signin.NewVerifier(signin.Endpoints{Identity: &down})
	if _, err = v(t.Context(), key); err == nil || errors.Is(err, signin.ErrRefused) {
		t.Fatalf("err %v, want a failure that is not a refusal", err)
	}
}

func TestVerifierWithoutIdentity(t *testing.T) {
	var seen []*http.Request
	s3 := service(t, 200, "application/xml", "<ListAllMyBucketsResult/>", &seen)
	v, _ := signin.NewVerifier(signin.Endpoints{ObjectStore: &s3})
	p, err := v(t.Context(), aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if p.ARN != "" || p.KeyHint != "" {
		t.Fatalf("principal %+v: a short key must not be shown", p)
	}
	if len(seen) != 1 || seen[0].URL.Path != "/" || seen[0].Method != http.MethodGet {
		t.Fatalf("asked %v, want ListBuckets", seen)
	}

	seen = nil
	refused := service(t, 403, "application/xml",
		`<Error><Code>InvalidAccessKeyId</Code><Message>no</Message></Error>`, &seen)
	v, _ = signin.NewVerifier(signin.Endpoints{ObjectStore: &refused})
	if _, err = v(t.Context(), key); !errors.Is(err, signin.ErrRefused) {
		t.Fatalf("err %v, want ErrRefused", err)
	}
}

func TestVerifierAcceptsNoOrganization(t *testing.T) {
	var seen []*http.Request
	acc := service(t, 400, "application/x-amz-json-1.1",
		`{"__type":"AWSOrganizationsNotInUseException","Message":"not in an organization"}`, &seen)
	v, _ := signin.NewVerifier(signin.Endpoints{Accounts: &acc})
	if _, err := v(t.Context(), key); err != nil {
		t.Fatalf("verify: %v; a key that got past the signature is accepted", err)
	}
}

func TestVerifierNeedsAService(t *testing.T) {
	if _, err := signin.NewVerifier(signin.Endpoints{}); err == nil {
		t.Fatal("a verifier with no service was made")
	}
}
