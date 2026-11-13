package consoletest

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// PolicyStore is the resource-based policies of a fake service, by the
// resource each is attached to, for the tests of the Policy sections. Its
// zero value is empty and ready.
type PolicyStore struct {
	docs map[string]string
	// Denied, when set, is the error every call answers, as a service
	// answers a principal its policies do not allow.
	Denied error
	mu     sync.Mutex
}

// Get returns the policy of res, and whether it has one.
func (s *PolicyStore) Get(res string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Denied != nil {
		return "", false, s.Denied
	}
	doc, ok := s.docs[res]
	return doc, ok, nil
}

// Put stores doc as the policy of res, refusing with code a document that
// is not JSON or has a statement without a Principal, as the services'
// policy parser does.
func (s *PolicyStore) Put(res, doc, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Denied != nil {
		return s.Denied
	}
	if msg := Malformed(doc); msg != "" {
		return ServiceError(http.StatusBadRequest, code, msg)
	}
	if s.docs == nil {
		s.docs = map[string]string{}
	}
	s.docs[res] = doc
	return nil
}

// Delete removes the policy of res.
func (s *PolicyStore) Delete(res string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Denied != nil {
		return s.Denied
	}
	delete(s.docs, res)
	return nil
}

// Malformed returns why doc is not a resource-based policy the fakes
// accept, or "" when it is one.
func Malformed(doc string) string {
	var p struct {
		Statement []map[string]json.RawMessage
	}
	if err := json.Unmarshal([]byte(doc), &p); err != nil {
		return "Policy document is not valid JSON."
	}
	for _, st := range p.Statement {
		if _, ok := st["Principal"]; !ok {
			return "Missing required field Principal."
		}
	}
	return ""
}

// ServiceError is an error a service answered with status, code and msg,
// as the SDK returns one.
func ServiceError(status int, code, msg string) error {
	return &awshttp.ResponseError{ResponseError: &smithyhttp.ResponseError{
		Response: &smithyhttp.Response{Response: &http.Response{StatusCode: status}},
		Err:      &smithy.GenericAPIError{Code: code, Message: msg},
	}}
}

// AccessDenied is a service's refusal of action, AccessDenied with 403.
func AccessDenied(action string) error {
	return Denied(http.StatusForbidden, "AccessDenied", action)
}

// Denied is a service's refusal of action with status and code, its
// message in IAM's form.
func Denied(status int, code, action string) error {
	return ServiceError(status, code, "User: "+strings.TrimSuffix(ARN, ":root")+
		":user/dev is not authorized to perform: "+action+
		" because no identity-based policy allows the "+action+" action")
}
