package web

import (
	"context"
	"errors"
	"net/http"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/smithy-go"

	"tule.dev/console/internal/awsclient"
)

// Failure is a service's failure as a page shows it: the status the console
// answers with, the service's error code when it gave one, and a message.
type Failure struct {
	Code    string
	Message string
	Status  int
}

// Describe describes err, an error of a service call. An error the service
// answered keeps its code and message, and its status when it is the
// caller's fault (4xx); a fault of the service, or no answer at all, is
// 502 Bad Gateway, and a call cut short is 504.
func Describe(err error) Failure {
	if err == nil {
		return Failure{Status: http.StatusOK}
	}
	if f, ok := consoleFailure(err); ok {
		return f
	}
	if e, ok := awsclient.AsAPIError(err); ok {
		msg := e.Message
		if msg == "" {
			msg = http.StatusText(e.Status)
		}
		return Failure{Code: e.Code, Message: msg, Status: consoleStatus(e.Status)}
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		status := 0
		var re *awshttp.ResponseError
		if errors.As(err, &re) {
			status = re.HTTPStatusCode()
		}
		msg := apiErr.ErrorMessage()
		if msg == "" {
			msg = apiErr.ErrorCode()
		}
		return Failure{Code: apiErr.ErrorCode(), Message: msg, Status: consoleStatus(status)}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return Failure{
			Message: "The service did not answer in time.",
			Status:  http.StatusGatewayTimeout,
		}
	}
	return Failure{
		Message: "The service could not be reached: " + err.Error(),
		Status:  http.StatusBadGateway,
	}
}

// consoleFailure describes the failures the console finds itself: a
// request it refuses, a thing it finds missing, and an answer that lacks a
// field.
func consoleFailure(err error) (Failure, bool) {
	var bad *BadInput
	if errors.As(err, &bad) {
		return Failure{Message: bad.Message, Status: http.StatusBadRequest}, true
	}
	var answer *MissingField
	if errors.As(err, &answer) {
		return Failure{
			Message: "The service answered " + answer.Operation + " without " + answer.Field + ".",
			Status:  http.StatusBadGateway,
		}, true
	}
	var changed *ChangedError
	if errors.As(err, &changed) {
		return Failure{Message: changed.Error(), Status: http.StatusConflict}, true
	}
	var missing *NotFoundError
	if errors.As(err, &missing) {
		return Failure{Message: missing.Message, Status: http.StatusNotFound}, true
	}
	return Failure{}, false
}

// consoleStatus maps the status a service answered to the console's: the
// caller's faults stand, a refused key is 403 either way, and anything
// else is the service's fault, 502.
func consoleStatus(status int) int {
	switch {
	case status == http.StatusUnauthorized:
		return http.StatusForbidden
	case status >= 400 && status < 500:
		return status
	default:
		return http.StatusBadGateway
	}
}

// Code returns the service's error code of err, or "".
func Code(err error) string {
	return Describe(err).Code
}

// BadInput is a request the console refuses before it calls a service.
type BadInput struct {
	Message string
}

func (e *BadInput) Error() string { return e.Message }

// NotFoundError is a thing the console looked for and the service does not
// have, found missing by the console rather than by the service.
type NotFoundError struct {
	Message string
}

func (e *NotFoundError) Error() string { return e.Message }

// MissingField is an answer of a service that lacks a field the console
// needs, such as a GetUser answer without its User: a fault of the service,
// shown as one rather than a panic.
type MissingField struct {
	Operation string
	Field     string
}

func (e *MissingField) Error() string {
	return "the service answered " + e.Operation + " without " + e.Field
}
