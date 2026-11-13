package mail_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sesv2/types"

	"tule.dev/console/internal/consoletest"
)

// fakeSES is the SES v2 API of identities in memory, each with its
// sending authorization policies by name.
type fakeSES struct {
	identities map[string]map[string]string
	// denied, when set, answers every policy call.
	denied error
	mu     sync.Mutex
}

func notFoundIdentity(name string) error {
	return consoletest.ServiceError(http.StatusNotFound, "NotFoundException",
		"Email identity "+name+" does not exist.")
}

func (f *fakeSES) ListEmailIdentities(
	context.Context, *sesv2.ListEmailIdentitiesInput, ...func(*sesv2.Options),
) (*sesv2.ListEmailIdentitiesOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := &sesv2.ListEmailIdentitiesOutput{}
	for n := range f.identities {
		out.EmailIdentities = append(out.EmailIdentities, types.IdentityInfo{
			IdentityName: aws.String(n), IdentityType: types.IdentityTypeDomain,
			VerificationStatus: types.VerificationStatusSuccess, SendingEnabled: true,
		})
	}
	return out, nil
}

func (f *fakeSES) GetEmailIdentity(
	_ context.Context, in *sesv2.GetEmailIdentityInput, _ ...func(*sesv2.Options),
) (*sesv2.GetEmailIdentityOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.identities[*in.EmailIdentity]; !ok {
		return nil, notFoundIdentity(*in.EmailIdentity)
	}
	return &sesv2.GetEmailIdentityOutput{
		IdentityType: types.IdentityTypeDomain, VerificationStatus: types.VerificationStatusSuccess,
		VerifiedForSendingStatus: true,
	}, nil
}

func (f *fakeSES) policies(identity string) (map[string]string, error) {
	if f.denied != nil {
		return nil, f.denied
	}
	p, ok := f.identities[identity]
	if !ok {
		return nil, notFoundIdentity(identity)
	}
	return p, nil
}

func (f *fakeSES) GetEmailIdentityPolicies(
	_ context.Context, in *sesv2.GetEmailIdentityPoliciesInput, _ ...func(*sesv2.Options),
) (*sesv2.GetEmailIdentityPoliciesOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, err := f.policies(*in.EmailIdentity)
	if err != nil {
		return nil, err
	}
	out := &sesv2.GetEmailIdentityPoliciesOutput{Policies: map[string]string{}}
	for k, v := range p {
		out.Policies[k] = v
	}
	return out, nil
}

func badRequest(doc string) error {
	if msg := consoletest.Malformed(doc); msg != "" {
		return consoletest.ServiceError(http.StatusBadRequest, "BadRequestException", msg)
	}
	return nil
}

func (f *fakeSES) CreateEmailIdentityPolicy(
	_ context.Context, in *sesv2.CreateEmailIdentityPolicyInput, _ ...func(*sesv2.Options),
) (*sesv2.CreateEmailIdentityPolicyOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, err := f.policies(*in.EmailIdentity)
	if err != nil {
		return nil, err
	}
	if _, ok := p[*in.PolicyName]; ok {
		return nil, consoletest.ServiceError(http.StatusBadRequest, "AlreadyExistsException",
			"Policy "+*in.PolicyName+" already exists.")
	}
	if err = badRequest(*in.Policy); err != nil {
		return nil, err
	}
	p[*in.PolicyName] = *in.Policy
	return &sesv2.CreateEmailIdentityPolicyOutput{}, nil
}

func (f *fakeSES) UpdateEmailIdentityPolicy(
	_ context.Context, in *sesv2.UpdateEmailIdentityPolicyInput, _ ...func(*sesv2.Options),
) (*sesv2.UpdateEmailIdentityPolicyOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, err := f.policies(*in.EmailIdentity)
	if err != nil {
		return nil, err
	}
	if err = badRequest(*in.Policy); err != nil {
		return nil, err
	}
	if _, ok := p[*in.PolicyName]; ok {
		p[*in.PolicyName] = *in.Policy
	}
	return &sesv2.UpdateEmailIdentityPolicyOutput{}, nil
}

func (f *fakeSES) DeleteEmailIdentityPolicy(
	_ context.Context, in *sesv2.DeleteEmailIdentityPolicyInput, _ ...func(*sesv2.Options),
) (*sesv2.DeleteEmailIdentityPolicyOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, err := f.policies(*in.EmailIdentity)
	if err != nil {
		return nil, err
	}
	delete(p, *in.PolicyName)
	return &sesv2.DeleteEmailIdentityPolicyOutput{}, nil
}

const sendPolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
	`"Principal":{"AWS":"111122223333"},"Action":"ses:SendEmail",` +
	`"Resource":"arn:aws:ses:us-east-1:000000000000:identity/example.com"}]}`

func TestIdentityPolicies(t *testing.T) {
	ses := &fakeSES{identities: map[string]map[string]string{"example.com": {}}}
	b := startWith(t, &fakeMailbox{}, ses)

	res := b.Get("/mail/identities")
	consoletest.RequireStatus(t, res, http.StatusOK)
	if consoletest.Find(res.Doc, consoletest.LinkTo("/mail/identity?name=example.com")) == nil {
		t.Fatal("no link to the identity")
	}
	res = b.Get("/mail/identity?name=example.com")
	consoletest.RequireText(
		t,
		res,
		"Sending authorization policies",
		"No policies.",
		"Add a policy",
	)
	ph, _ := consoletest.Attr(
		consoletest.Find(res.Doc, consoletest.ByID("policy-new-document")),
		"placeholder",
	)
	if !strings.Contains(ph, `"arn:aws:ses:us-east-1:000000000000:identity/example.com"`) {
		t.Fatalf("the example does not name the identity: %s", ph)
	}

	// Create two, the second refused first for its document.
	for _, name := range []string{"partner", "other"} {
		res = b.PostForm("/mail/identity/policy", url.Values{
			"identity": {"example.com"}, "name": {name}, "new": {"true"}, "document": {sendPolicy},
		})
		consoletest.RequireFlash(
			t,
			b.Get(res.Location()),
			"ok",
			"Created policy "+name+" of example.com.",
		)
	}
	bad := `{"Statement":[{"Effect":"Allow"}]}`
	res = b.PostForm("/mail/identity/policy", url.Values{
		"identity": {"example.com"}, "name": {"third"}, "new": {"true"}, "document": {bad},
	})
	consoletest.RequireStatus(t, res, http.StatusBadRequest)
	consoletest.RequireText(t, res, "The service answered BadRequestException.")
	if consoletest.Find(res.Doc, consoletest.ByID("policy-new-error")) == nil {
		t.Fatal("the refusal is not next to the new policy's form")
	}
	if !holdsName(res, "third") {
		t.Fatal("the new policy's form lost the typed name")
	}

	editAndDelete(t, b, ses)
}

// editAndDelete edits and deletes the policies TestIdentityPolicies made.
func editAndDelete(t *testing.T, b *consoletest.Browser, ses *fakeSES) {
	t.Helper()
	bad := `{"Statement":[{"Effect":"Allow"}]}`
	// A name the identity has is refused by mailbox, next to the form.
	res := b.PostForm("/mail/identity/policy", url.Values{
		"identity": {"example.com"}, "name": {"partner"}, "new": {"true"}, "document": {sendPolicy},
	})
	consoletest.RequireText(t, res, "AlreadyExistsException")

	// Each stored policy has its own form; editing one keeps the other.
	page := b.Get("/mail/identity?name=example.com")
	if n := len(
		consoletest.FindAll(page.Doc, consoletest.FormTo("/mail/identity/policy/delete")),
	); n != 2 {
		t.Fatalf("%d delete forms, want one for each policy", n)
	}
	res = b.PostForm("/mail/identity/policy", url.Values{
		"identity": {"example.com"}, "name": {"partner"}, "document": {bad},
	})
	consoletest.RequireStatus(t, res, http.StatusBadRequest)
	if consoletest.Find(res.Doc, consoletest.ByID("policy-partner-error")) == nil {
		t.Fatal("the refusal is not next to the edited policy's form")
	}
	edited := strings.Replace(sendPolicy, "ses:SendEmail", "ses:SendRawEmail", 1)
	res = b.PostForm("/mail/identity/policy", url.Values{
		"identity": {"example.com"}, "name": {"partner"}, "document": {edited},
	})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Saved policy partner of example.com.")
	if ses.identities["example.com"]["partner"] != edited ||
		ses.identities["example.com"]["other"] != sendPolicy {
		t.Fatalf("policies after the edit: %v", ses.identities["example.com"])
	}

	res = b.PostForm("/mail/identity/policy/delete", url.Values{
		"identity": {"example.com"}, "name": {"other"},
	})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Deleted policy other of example.com.")
	if _, ok := ses.identities["example.com"]["other"]; ok {
		t.Fatal("the policy was not deleted")
	}
}

func TestIdentityPoliciesDenied(t *testing.T) {
	ses := &fakeSES{
		identities: map[string]map[string]string{"example.com": {}},
		denied:     consoletest.AccessDenied("ses:GetEmailIdentityPolicies"),
	}
	b := startWith(t, &fakeMailbox{}, ses)
	res := b.Get("/mail/identity?name=example.com")
	consoletest.RequireStatus(t, res, http.StatusOK)
	consoletest.RequireText(t, res, "Verification", "The policies could not be read.",
		"The service answered AccessDenied.", "ses:GetEmailIdentityPolicies")
}

// holdsName reports whether a policy name field of the page holds name.
func holdsName(res *consoletest.Response, name string) bool {
	for _, n := range consoletest.FindAll(res.Doc, consoletest.ByName("name")) {
		if v, _ := consoletest.Attr(n, "value"); v == name {
			return true
		}
	}
	return false
}
