// Package awsclient builds the clients the console calls the services
// with: the aws-sdk-go-v2 client of each AWS API, the SigV4-signed JSON
// client of the services' own retrieval and inspection APIs, and the
// readiness probe.
//
// Every client is built per request from the signed-in session's
// credentials, so nothing here holds a credential beyond one call.
package awsclient

import (
	"net"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// Endpoint is one service the console calls: its base URL, the region the
// console signs for, and the HTTP client every call goes through.
type Endpoint struct {
	HTTP   *http.Client
	URL    string
	Region string
}

// NewHTTPClient returns the HTTP client the console calls the services
// with. It has no overall timeout, since a download streams for as long as
// the object takes; a connection must open within 10s and a response's
// headers arrive within 5 minutes, the console's own write timeout, which
// a synchronous function invocation may take; the browser's request bounds
// the rest.
func NewHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
			ResponseHeaderTimeout: 5 * time.Minute,
			MaxIdleConnsPerHost:   16,
			IdleConnTimeout:       90 * time.Second,
		},
		// A service never redirects an API call; following one would send
		// the signed request elsewhere.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func provider(creds aws.Credentials) aws.CredentialsProvider {
	return credentials.StaticCredentialsProvider{Value: creds}
}

// The SDK clients do not retry: an action the console runs is run once,
// and a failure is shown at once rather than after the SDK's backoff.

// S3 returns an S3 client for e, path-style, as object-store serves it.
func S3(e Endpoint, creds aws.Credentials) *s3.Client {
	return s3.New(s3.Options{
		Region:           e.Region,
		BaseEndpoint:     aws.String(e.URL),
		Credentials:      provider(creds),
		HTTPClient:       e.HTTP,
		UsePathStyle:     true,
		RetryMaxAttempts: 1,
	})
}

// SecretsManager returns a Secrets Manager client for e.
func SecretsManager(e Endpoint, creds aws.Credentials) *secretsmanager.Client {
	return secretsmanager.New(secretsmanager.Options{
		Region:           e.Region,
		BaseEndpoint:     aws.String(e.URL),
		Credentials:      provider(creds),
		HTTPClient:       e.HTTP,
		RetryMaxAttempts: 1,
	})
}

// Organizations returns an Organizations client for e.
func Organizations(e Endpoint, creds aws.Credentials) *organizations.Client {
	return organizations.New(organizations.Options{
		Region:           e.Region,
		BaseEndpoint:     aws.String(e.URL),
		Credentials:      provider(creds),
		HTTPClient:       e.HTTP,
		RetryMaxAttempts: 1,
	})
}

// IAM returns an IAM client for e.
func IAM(e Endpoint, creds aws.Credentials) *iam.Client {
	return iam.New(iam.Options{
		Region:           e.Region,
		BaseEndpoint:     aws.String(e.URL),
		Credentials:      provider(creds),
		HTTPClient:       e.HTTP,
		RetryMaxAttempts: 1,
	})
}

// STS returns an STS client for e.
func STS(e Endpoint, creds aws.Credentials) *sts.Client {
	return sts.New(sts.Options{
		Region:           e.Region,
		BaseEndpoint:     aws.String(e.URL),
		Credentials:      provider(creds),
		HTTPClient:       e.HTTP,
		RetryMaxAttempts: 1,
	})
}

// SESv2 returns an SES v2 client for e.
func SESv2(e Endpoint, creds aws.Credentials) *sesv2.Client {
	return sesv2.New(sesv2.Options{
		Region:           e.Region,
		BaseEndpoint:     aws.String(e.URL),
		Credentials:      provider(creds),
		HTTPClient:       e.HTTP,
		RetryMaxAttempts: 1,
	})
}

// SQS returns an SQS client for e.
func SQS(e Endpoint, creds aws.Credentials) *sqs.Client {
	return sqs.New(sqs.Options{
		Region:           e.Region,
		BaseEndpoint:     aws.String(e.URL),
		Credentials:      provider(creds),
		HTTPClient:       e.HTTP,
		RetryMaxAttempts: 1,
	})
}

// Lambda returns a Lambda client for e.
func Lambda(e Endpoint, creds aws.Credentials) *lambda.Client {
	return lambda.New(lambda.Options{
		Region:           e.Region,
		BaseEndpoint:     aws.String(e.URL),
		Credentials:      provider(creds),
		HTTPClient:       e.HTTP,
		RetryMaxAttempts: 1,
	})
}
