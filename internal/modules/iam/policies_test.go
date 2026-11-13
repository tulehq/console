package iam_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"tule.dev/console/internal/app"
	"tule.dev/console/internal/consoletest"
	consoleiam "tule.dev/console/internal/modules/iam"
)

const (
	adminARN = "arn:aws:iam::aws:policy/AdministratorAccess"
	adminDoc = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
	readDoc  = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListAllMyBuckets","Resource":"*"}]}`
	trustDoc = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
		`"Principal":{"AWS":"arn:aws:iam::000000000000:root"},"Action":"sts:AssumeRole"}]}`
)

type role struct {
	inline   map[string]string
	name     string
	trust    string
	attached []string
}

type managed struct {
	name string
	doc  string
}

// answered is err as the SDK returns a service's answer: with its HTTP
// status, so the console shows it with that status.
func answered(status int, code, message string) error {
	return &awshttp.ResponseError{ResponseError: &smithyhttp.ResponseError{
		Response: &smithyhttp.Response{Response: &http.Response{StatusCode: status}},
		Err:      &smithy.GenericAPIError{Code: code, Message: message},
	}}
}

// checkDoc refuses a document that is not JSON, as identity refuses one
// that breaks the policy grammar.
func checkDoc(doc string) error {
	if !json.Valid([]byte(doc)) {
		return answered(400, "MalformedPolicyDocument", "Syntax errors in policy.")
	}
	return nil
}

// encoded is a document as IAM answers it, URL-encoded.
func encoded(doc string) *string { return aws.String(url.QueryEscape(doc)) }

func (f *fakeIAM) ListUserPolicies(
	_ context.Context, in *iam.ListUserPoliciesInput, _ ...func(*iam.Options),
) (*iam.ListUserPoliciesOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, err := f.find(*in.UserName)
	if err != nil {
		return nil, err
	}
	return &iam.ListUserPoliciesOutput{PolicyNames: sortedKeys(u.inline)}, nil
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (f *fakeIAM) GetUserPolicy(
	_ context.Context, in *iam.GetUserPolicyInput, _ ...func(*iam.Options),
) (*iam.GetUserPolicyOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, err := f.find(*in.UserName)
	if err != nil {
		return nil, err
	}
	doc, ok := u.inline[*in.PolicyName]
	if !ok {
		return nil, noSuch(*in.PolicyName)
	}
	return &iam.GetUserPolicyOutput{PolicyName: in.PolicyName, PolicyDocument: encoded(doc)}, nil
}

func (f *fakeIAM) PutUserPolicy(
	_ context.Context, in *iam.PutUserPolicyInput, _ ...func(*iam.Options),
) (*iam.PutUserPolicyOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, err := f.find(*in.UserName)
	if err != nil {
		return nil, err
	}
	if err = checkDoc(*in.PolicyDocument); err != nil {
		return nil, err
	}
	if u.inline == nil {
		u.inline = map[string]string{}
	}
	u.inline[*in.PolicyName] = *in.PolicyDocument
	return &iam.PutUserPolicyOutput{}, nil
}

func (f *fakeIAM) DeleteUserPolicy(
	_ context.Context, in *iam.DeleteUserPolicyInput, _ ...func(*iam.Options),
) (*iam.DeleteUserPolicyOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, err := f.find(*in.UserName)
	if err != nil {
		return nil, err
	}
	if _, ok := u.inline[*in.PolicyName]; !ok {
		return nil, noSuch(*in.PolicyName)
	}
	delete(u.inline, *in.PolicyName)
	return &iam.DeleteUserPolicyOutput{}, nil
}

func (f *fakeIAM) attachedOf(arns []string) []types.AttachedPolicy {
	out := make([]types.AttachedPolicy, 0, len(arns))
	for _, a := range arns {
		out = append(out, types.AttachedPolicy{
			PolicyArn: aws.String(a), PolicyName: aws.String(f.managed[a].name),
		})
	}
	return out
}

func (f *fakeIAM) ListAttachedUserPolicies(
	_ context.Context, in *iam.ListAttachedUserPoliciesInput, _ ...func(*iam.Options),
) (*iam.ListAttachedUserPoliciesOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, err := f.find(*in.UserName)
	if err != nil {
		return nil, err
	}
	return &iam.ListAttachedUserPoliciesOutput{AttachedPolicies: f.attachedOf(u.attached)}, nil
}

func (f *fakeIAM) attachTo(list *[]string, arn string) error {
	if _, ok := f.managed[arn]; !ok {
		return noSuch(arn)
	}
	if !slices.Contains(*list, arn) {
		*list = append(*list, arn)
	}
	return nil
}

func detachFrom(list *[]string, arn string) error {
	i := slices.Index(*list, arn)
	if i < 0 {
		return noSuch(arn)
	}
	*list = slices.Delete(*list, i, i+1)
	return nil
}

func (f *fakeIAM) AttachUserPolicy(
	_ context.Context, in *iam.AttachUserPolicyInput, _ ...func(*iam.Options),
) (*iam.AttachUserPolicyOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, err := f.find(*in.UserName)
	if err != nil {
		return nil, err
	}
	return &iam.AttachUserPolicyOutput{}, f.attachTo(&u.attached, *in.PolicyArn)
}

func (f *fakeIAM) DetachUserPolicy(
	_ context.Context, in *iam.DetachUserPolicyInput, _ ...func(*iam.Options),
) (*iam.DetachUserPolicyOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, err := f.find(*in.UserName)
	if err != nil {
		return nil, err
	}
	return &iam.DetachUserPolicyOutput{}, detachFrom(&u.attached, *in.PolicyArn)
}

func (f *fakeIAM) policyOf(arn string) types.Policy {
	p := f.managed[arn]
	return types.Policy{
		Arn: aws.String(arn), PolicyName: aws.String(p.name), PolicyId: aws.String("ANPA" + p.name),
		Path: aws.String("/"), DefaultVersionId: aws.String("v1"),
		CreateDate: aws.Time(time.Unix(0, 0)), UpdateDate: aws.Time(time.Unix(0, 0)),
		AttachmentCount: aws.Int32(0),
	}
}

func (f *fakeIAM) ListPolicies(
	_ context.Context, _ *iam.ListPoliciesInput, _ ...func(*iam.Options),
) (*iam.ListPoliciesOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	arns := make([]string, 0, len(f.managed))
	for a := range f.managed {
		arns = append(arns, a)
	}
	sort.Strings(arns)
	out := &iam.ListPoliciesOutput{}
	for _, a := range arns {
		out.Policies = append(out.Policies, f.policyOf(a))
	}
	return out, nil
}

func (f *fakeIAM) GetPolicy(
	_ context.Context, in *iam.GetPolicyInput, _ ...func(*iam.Options),
) (*iam.GetPolicyOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.managed[*in.PolicyArn]; !ok {
		return nil, noSuch(*in.PolicyArn)
	}
	p := f.policyOf(*in.PolicyArn)
	return &iam.GetPolicyOutput{Policy: &p}, nil
}

func (f *fakeIAM) GetPolicyVersion(
	_ context.Context, in *iam.GetPolicyVersionInput, _ ...func(*iam.Options),
) (*iam.GetPolicyVersionOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.managed[*in.PolicyArn]
	if !ok || *in.VersionId != "v1" {
		return nil, noSuch(*in.PolicyArn)
	}
	return &iam.GetPolicyVersionOutput{PolicyVersion: &types.PolicyVersion{
		Document: encoded(p.doc), VersionId: aws.String("v1"), IsDefaultVersion: true,
	}}, nil
}

func (f *fakeIAM) CreatePolicy(
	_ context.Context, in *iam.CreatePolicyInput, _ ...func(*iam.Options),
) (*iam.CreatePolicyOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := checkDoc(*in.PolicyDocument); err != nil {
		return nil, err
	}
	arn := "arn:aws:iam::000000000000:policy/" + *in.PolicyName
	f.managed[arn] = &managed{name: *in.PolicyName, doc: *in.PolicyDocument}
	p := f.policyOf(arn)
	return &iam.CreatePolicyOutput{Policy: &p}, nil
}

func (f *fakeIAM) DeletePolicy(
	_ context.Context, in *iam.DeletePolicyInput, _ ...func(*iam.Options),
) (*iam.DeletePolicyOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.managed[*in.PolicyArn]; !ok {
		return nil, noSuch(*in.PolicyArn)
	}
	for _, u := range f.users {
		if slices.Contains(u.attached, *in.PolicyArn) {
			return nil, answered(
				409,
				"DeleteConflict",
				"Cannot delete a policy attached to entities.",
			)
		}
	}
	for _, r := range f.roles {
		if slices.Contains(r.attached, *in.PolicyArn) {
			return nil, answered(
				409,
				"DeleteConflict",
				"Cannot delete a policy attached to entities.",
			)
		}
	}
	delete(f.managed, *in.PolicyArn)
	return &iam.DeletePolicyOutput{}, nil
}

func (f *fakeIAM) findRole(name string) (*role, error) {
	r, ok := f.roles[name]
	if !ok {
		return nil, answered(404, "NoSuchEntity", "The role with name "+name+" cannot be found.")
	}
	return r, nil
}

func roleOf(r *role) types.Role {
	return types.Role{
		RoleName: aws.String(r.name), Arn: aws.String("arn:aws:iam::000000000000:role/" + r.name),
		RoleId: aws.String("AROA" + r.name), Path: aws.String("/"),
		CreateDate: aws.Time(time.Unix(0, 0)), MaxSessionDuration: aws.Int32(3600),
		AssumeRolePolicyDocument: encoded(r.trust),
	}
}

func (f *fakeIAM) ListRoles(
	_ context.Context, _ *iam.ListRolesInput, _ ...func(*iam.Options),
) (*iam.ListRolesOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	names := make([]string, 0, len(f.roles))
	for n := range f.roles {
		names = append(names, n)
	}
	sort.Strings(names)
	out := &iam.ListRolesOutput{}
	for _, n := range names {
		out.Roles = append(out.Roles, roleOf(f.roles[n]))
	}
	return out, nil
}

func (f *fakeIAM) GetRole(
	_ context.Context, in *iam.GetRoleInput, _ ...func(*iam.Options),
) (*iam.GetRoleOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, err := f.findRole(*in.RoleName)
	if err != nil {
		return nil, err
	}
	out := roleOf(r)
	return &iam.GetRoleOutput{Role: &out}, nil
}

func (f *fakeIAM) CreateRole(
	_ context.Context, in *iam.CreateRoleInput, _ ...func(*iam.Options),
) (*iam.CreateRoleOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := checkDoc(*in.AssumeRolePolicyDocument); err != nil {
		return nil, err
	}
	r := &role{name: *in.RoleName, trust: *in.AssumeRolePolicyDocument}
	f.roles[r.name] = r
	out := roleOf(r)
	return &iam.CreateRoleOutput{Role: &out}, nil
}

func (f *fakeIAM) DeleteRole(
	_ context.Context, in *iam.DeleteRoleInput, _ ...func(*iam.Options),
) (*iam.DeleteRoleOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, err := f.findRole(*in.RoleName)
	if err != nil {
		return nil, err
	}
	if len(r.inline) > 0 || len(r.attached) > 0 {
		return nil, answered(
			409,
			"DeleteConflict",
			"Cannot delete entity, must detach all policies first.",
		)
	}
	delete(f.roles, r.name)
	return &iam.DeleteRoleOutput{}, nil
}

func (f *fakeIAM) ListRolePolicies(
	_ context.Context, in *iam.ListRolePoliciesInput, _ ...func(*iam.Options),
) (*iam.ListRolePoliciesOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, err := f.findRole(*in.RoleName)
	if err != nil {
		return nil, err
	}
	return &iam.ListRolePoliciesOutput{PolicyNames: sortedKeys(r.inline)}, nil
}

func (f *fakeIAM) GetRolePolicy(
	_ context.Context, in *iam.GetRolePolicyInput, _ ...func(*iam.Options),
) (*iam.GetRolePolicyOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, err := f.findRole(*in.RoleName)
	if err != nil {
		return nil, err
	}
	doc, ok := r.inline[*in.PolicyName]
	if !ok {
		return nil, noSuch(*in.PolicyName)
	}
	return &iam.GetRolePolicyOutput{PolicyName: in.PolicyName, PolicyDocument: encoded(doc)}, nil
}

func (f *fakeIAM) PutRolePolicy(
	_ context.Context, in *iam.PutRolePolicyInput, _ ...func(*iam.Options),
) (*iam.PutRolePolicyOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, err := f.findRole(*in.RoleName)
	if err != nil {
		return nil, err
	}
	if err = checkDoc(*in.PolicyDocument); err != nil {
		return nil, err
	}
	if r.inline == nil {
		r.inline = map[string]string{}
	}
	r.inline[*in.PolicyName] = *in.PolicyDocument
	return &iam.PutRolePolicyOutput{}, nil
}

func (f *fakeIAM) DeleteRolePolicy(
	_ context.Context, in *iam.DeleteRolePolicyInput, _ ...func(*iam.Options),
) (*iam.DeleteRolePolicyOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, err := f.findRole(*in.RoleName)
	if err != nil {
		return nil, err
	}
	delete(r.inline, *in.PolicyName)
	return &iam.DeleteRolePolicyOutput{}, nil
}

func (f *fakeIAM) ListAttachedRolePolicies(
	_ context.Context, in *iam.ListAttachedRolePoliciesInput, _ ...func(*iam.Options),
) (*iam.ListAttachedRolePoliciesOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, err := f.findRole(*in.RoleName)
	if err != nil {
		return nil, err
	}
	return &iam.ListAttachedRolePoliciesOutput{AttachedPolicies: f.attachedOf(r.attached)}, nil
}

func (f *fakeIAM) AttachRolePolicy(
	_ context.Context, in *iam.AttachRolePolicyInput, _ ...func(*iam.Options),
) (*iam.AttachRolePolicyOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, err := f.findRole(*in.RoleName)
	if err != nil {
		return nil, err
	}
	return &iam.AttachRolePolicyOutput{}, f.attachTo(&r.attached, *in.PolicyArn)
}

func (f *fakeIAM) DetachRolePolicy(
	_ context.Context, in *iam.DetachRolePolicyInput, _ ...func(*iam.Options),
) (*iam.DetachRolePolicyOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, err := f.findRole(*in.RoleName)
	if err != nil {
		return nil, err
	}
	return &iam.DetachRolePolicyOutput{}, detachFrom(&r.attached, *in.PolicyArn)
}

// textarea returns the text of the page's textarea named name.
func textarea(t *testing.T, res *consoletest.Response, name string) string {
	t.Helper()
	n := consoletest.Find(res.Doc, consoletest.ByName(name))
	if n == nil {
		t.Fatalf("the page has no field %s: %s", name, consoletest.Text(res.Doc))
	}
	return consoletest.Text(n)
}

func TestFormatPolicy(t *testing.T) {
	got := consoleiam.FormatPolicy(url.QueryEscape(`{"Version":"2012-10-17","Statement":[]}`))
	if got != "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": []\n}" {
		t.Fatalf("formatted %q", got)
	}
	if got = consoleiam.FormatPolicy("not json %"); got != "not json %" {
		t.Fatalf("a document that is not JSON became %q", got)
	}
}

func TestUserInlinePolicies(t *testing.T) {
	f := newFake()
	f.users["ops"] = &user{name: "ops"}
	b := start(t, f)

	res := b.Get("/iam/user?name=ops")
	consoletest.RequireText(t, res, "Inline policies", "No inline policies.", "Attached policies")
	res = b.Get(consoletest.Href(res.Doc, "Add inline policy"))
	consoletest.RequireStatus(t, res, http.StatusOK)

	// A document identity refuses is shown next to the form, as typed.
	res = b.PostForm("/iam/user/policy", url.Values{
		"user": {"ops"}, "name": {"read"}, "new": {"true"}, "document": {"{not json"},
	})
	consoletest.RequireStatus(t, res, http.StatusBadRequest)
	consoletest.RequireText(t, res, "MalformedPolicyDocument", "Syntax errors in policy.")
	if got := textarea(t, res, "document"); got != "{not json" {
		t.Fatalf("the form lost the document: %q", got)
	}
	if consoletest.Find(res.Doc, consoletest.ByID("form-error")) == nil {
		t.Fatal("the failure is not next to the form")
	}

	res = b.PostForm("/iam/user/policy", url.Values{
		"user": {"ops"}, "name": {"read"}, "new": {"true"}, "document": {readDoc},
	})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Saved inline policy read of ops.")
	if f.users["ops"].inline["read"] != readDoc {
		t.Fatalf("inline policies %v", f.users["ops"].inline)
	}

	// The document is shown decoded and indented, to edit.
	res = b.Get("/iam/user?name=ops")
	res = b.Get(consoletest.Href(res.Doc, "read"))
	if got := textarea(t, res, "document"); !strings.Contains(got,
		"\"Action\": \"s3:ListAllMyBuckets\"") {
		t.Fatalf("document %q", got)
	}

	res = b.PostForm("/iam/user/policy/delete", url.Values{"user": {"ops"}, "name": {"read"}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Deleted inline policy read")
	if len(f.users["ops"].inline) != 0 {
		t.Fatal("the inline policy was not deleted")
	}
}

func TestUserAttachedPolicies(t *testing.T) {
	f := newFake()
	f.users["ops"] = &user{name: "ops"}
	b := start(t, f)

	res := b.Get("/iam/user?name=ops")
	consoletest.RequireText(t, res, "AdministratorAccess ("+adminARN+")")
	res = b.PostForm("/iam/user/attach", url.Values{"user": {"ops"}, "arn": {adminARN}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Attached "+adminARN+" to ops.")
	res = b.Get("/iam/user?name=ops")
	consoletest.RequireText(t, res, "Detach")

	// A user with policies is not deleted, and says why.
	res = b.PostForm("/iam/users/delete", url.Values{"name": {"ops"}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "error", "must delete policies first")

	res = b.PostForm("/iam/user/detach", url.Values{"user": {"ops"}, "arn": {adminARN}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Detached "+adminARN+" from ops.")
	if len(f.users["ops"].attached) != 0 {
		t.Fatal("the policy is still attached")
	}
}

func TestRoles(t *testing.T) {
	f := newFake()
	b := start(t, f)

	res := b.Get("/iam/roles")
	consoletest.RequireText(t, res, "No roles yet.")
	res = b.Get("/iam/roles/new")
	if got := textarea(t, res, "trust"); !strings.Contains(got, "arn:aws:iam::000000000000:root") {
		t.Fatalf("the trust policy starts as %q, not trusting the account", got)
	}

	res = b.PostForm("/iam/roles", url.Values{"name": {"deployer"}, "trust": {"{"}})
	consoletest.RequireStatus(t, res, http.StatusBadRequest)
	consoletest.RequireText(t, res, "MalformedPolicyDocument")
	if got := textarea(t, res, "trust"); got != "{" {
		t.Fatalf("the form lost the trust policy: %q", got)
	}
	res = b.PostForm("/iam/roles", url.Values{
		"name": {"deployer"}, "trust": {trustDoc},
		"maxSession": {"many"},
	})
	consoletest.RequireStatus(t, res, http.StatusBadRequest)
	consoletest.RequireText(t, res, "a number of seconds")

	res = b.PostForm("/iam/roles", url.Values{"name": {"deployer"}, "trust": {trustDoc}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Created role deployer.")
	res = b.Get("/iam/role?name=deployer")
	consoletest.RequireText(t, res, "arn:aws:iam::000000000000:role/deployer", `"sts:AssumeRole"`)

	res = b.PostForm("/iam/role/attach", url.Values{"role": {"deployer"}, "arn": {adminARN}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Attached "+adminARN+" to deployer.")
	res = b.PostForm("/iam/role/policy", url.Values{
		"role": {"deployer"}, "name": {"read"}, "new": {"true"}, "document": {readDoc},
	})
	consoletest.RequireFlash(
		t,
		b.Get(res.Location()),
		"ok",
		"Saved inline policy read of deployer.",
	)
	res = b.Get("/iam/role?name=deployer")
	consoletest.RequireText(t, res, "AdministratorAccess", "read")

	res = b.PostForm("/iam/roles/delete", url.Values{"name": {"deployer"}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "error", "must detach all policies first")

	b.PostForm("/iam/role/detach", url.Values{"role": {"deployer"}, "arn": {adminARN}})
	b.PostForm("/iam/role/policy/delete", url.Values{"role": {"deployer"}, "name": {"read"}})
	res = b.PostForm("/iam/roles/delete", url.Values{"name": {"deployer"}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Deleted role deployer.")
	if len(f.roles) != 0 {
		t.Fatal("the role was not deleted")
	}
}

func TestManagedPolicies(t *testing.T) {
	f := newFake()
	b := start(t, f)

	res := b.Get("/iam/policies")
	consoletest.RequireText(t, res, "AdministratorAccess", "AWS managed")
	res = b.Get("/iam/policy?arn=" + url.QueryEscape(adminARN))
	consoletest.RequireText(t, res, "default version v1", `"Action": "*"`)
	if consoletest.Find(res.Doc, consoletest.ByName("arn")) != nil {
		t.Fatal("an AWS managed policy offers to delete it")
	}

	b.Get("/iam/policies/new")
	res = b.PostForm("/iam/policies", url.Values{"name": {"read"}, "document": {"nope"}})
	consoletest.RequireStatus(t, res, http.StatusBadRequest)
	consoletest.RequireText(t, res, "MalformedPolicyDocument")
	res = b.PostForm("/iam/policies", url.Values{"name": {""}, "document": {readDoc}})
	consoletest.RequireStatus(t, res, http.StatusBadRequest)
	consoletest.RequireText(t, res, "Enter a policy name.")

	res = b.PostForm("/iam/policies", url.Values{"name": {"read"}, "document": {readDoc}})
	page := b.Get(res.Location())
	consoletest.RequireFlash(t, page, "ok", "Created policy read.")
	consoletest.RequireText(t, page, "arn:aws:iam::000000000000:policy/read", "Customer managed")

	arn := "arn:aws:iam::000000000000:policy/read"
	f.users["ops"] = &user{name: "ops", attached: []string{arn}}
	res = b.PostForm("/iam/policies/delete", url.Values{"arn": {arn}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "error", "attached to entities")
	f.users["ops"].attached = nil
	res = b.PostForm("/iam/policies/delete", url.Values{"arn": {arn}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Deleted policy "+arn)
}

// deniedIAM denies every policy read, as identity denies a principal
// without iam:ListUserPolicies and the like.
type deniedIAM struct{ *fakeIAM }

func denied(action string) error {
	return answered(403, "AccessDenied", "User: arn:aws:iam::000000000000:user/dev is not "+
		"authorized to perform: "+action+" on resource: * because no identity-based policy "+
		"allows the "+action+" action")
}

func (deniedIAM) ListUserPolicies(
	context.Context, *iam.ListUserPoliciesInput, ...func(*iam.Options),
) (*iam.ListUserPoliciesOutput, error) {
	return nil, denied("iam:ListUserPolicies")
}

func (deniedIAM) ListAttachedUserPolicies(
	context.Context, *iam.ListAttachedUserPoliciesInput, ...func(*iam.Options),
) (*iam.ListAttachedUserPoliciesOutput, error) {
	return nil, denied("iam:ListAttachedUserPolicies")
}

func (deniedIAM) ListPolicies(
	context.Context, *iam.ListPoliciesInput, ...func(*iam.Options),
) (*iam.ListPoliciesOutput, error) {
	return nil, denied("iam:ListPolicies")
}

func (deniedIAM) ListRoles(
	context.Context, *iam.ListRolesInput, ...func(*iam.Options),
) (*iam.ListRolesOutput, error) {
	return nil, denied("iam:ListRoles")
}

func TestPolicyReadsDenied(t *testing.T) {
	f := newFake()
	f.users["ops"] = &user{name: "ops"}
	s := consoletest.Start(
		t,
		app.Overrides{
			IAM: func(aws.Credentials) consoleiam.API { return deniedIAM{f} },
		},
		nil,
		"iam",
	)
	b := s.Browser(t)
	b.SignIn(consoletest.KeyID, consoletest.Secret)

	// The IAM user is shown; each list it may not read says so in its place.
	res := b.Get("/iam/user?name=ops")
	consoletest.RequireStatus(t, res, http.StatusOK)
	consoletest.RequireText(t, res, "iam:ListUserPolicies", "iam:ListAttachedUserPolicies",
		"The policies could not be listed", "iam:ListPolicies")
	if consoletest.Find(res.Doc, consoletest.ByName("arn")) == nil {
		t.Fatal("without the list, the attach form takes no ARN")
	}

	res = b.Get("/iam/roles")
	consoletest.RequireStatus(t, res, http.StatusForbidden)
	consoletest.RequireText(t, res, "The service answered AccessDenied.", "iam:ListRoles")
	res = b.Get("/iam/policies")
	consoletest.RequireStatus(t, res, http.StatusForbidden)
	consoletest.RequireText(t, res, "iam:ListPolicies")
}

func TestHostilePoliciesRenderInert(t *testing.T) {
	f := newFake()
	for _, h := range consoletest.Hostile {
		f.users[h] = &user{name: h, inline: map[string]string{h: h}}
		f.roles[h] = &role{name: h, trust: h, inline: map[string]string{h: h}}
		f.managed["arn:aws:iam::000000000000:policy/"+h] = &managed{name: h, doc: h}
	}
	b := start(t, f)
	for _, path := range []string{"/iam/roles", "/iam/policies"} {
		res := b.Get(path)
		consoletest.RequireInert(t, res)
		consoletest.RequireText(t, res, consoletest.Hostile...)
	}
	for _, h := range consoletest.Hostile {
		q := url.QueryEscape(h)
		for _, path := range []string{
			"/iam/user?name=" + q, "/iam/role?name=" + q,
			"/iam/user/policy?user=" + q + "&name=" + q, "/iam/role/policy?role=" + q + "&name=" + q,
			"/iam/policy?arn=" + url.QueryEscape("arn:aws:iam::000000000000:policy/"+h),
		} {
			res := b.Get(path)
			consoletest.RequireStatus(t, res, http.StatusOK)
			consoletest.RequireInert(t, res)
		}
	}
	res := b.PostForm("/iam/roles", url.Values{
		"name":  {consoletest.Hostile[0]},
		"trust": {consoletest.Hostile[0]},
	})
	consoletest.RequireInert(t, res)
}

func TestNewInlinePolicyKeepsAnExistingOne(t *testing.T) {
	f := newFake()
	f.users["ops"] = &user{name: "ops", inline: map[string]string{"read": readDoc}}
	f.roles["deployer"] = &role{
		name: "deployer", trust: trustDoc, inline: map[string]string{"read": readDoc},
	}
	b := start(t, f)

	for _, kind := range []string{"user", "role"} {
		owner := map[string]string{"user": "ops", "role": "deployer"}[kind]
		b.Get("/iam/" + kind + "/policy?" + kind + "=" + owner)
		res := b.PostForm("/iam/"+kind+"/policy", url.Values{
			kind: {owner}, "name": {"read"}, "new": {"true"}, "document": {adminDoc},
		})
		consoletest.RequireStatus(t, res, http.StatusBadRequest)
		consoletest.RequireText(t, res, owner+" already has an inline policy named read.")
		if got := textarea(t, res, "document"); got != adminDoc {
			t.Fatalf("%s: the form lost the document: %q", kind, got)
		}
		if consoletest.Find(res.Doc, consoletest.ByID("form-error")) == nil {
			t.Fatalf("%s: the refusal is not next to the form", kind)
		}

		// Saved from its own page, the policy is changed, as asked.
		res = b.PostForm("/iam/"+kind+"/policy", url.Values{
			kind: {owner}, "name": {"read"}, "document": {adminDoc},
		})
		consoletest.RequireStatus(t, res, http.StatusSeeOther)
	}
	if f.users["ops"].inline["read"] != adminDoc || f.roles["deployer"].inline["read"] != adminDoc {
		t.Fatal("saving an existing policy from its page did not change it")
	}
}

func TestAttachListCutAtItsLimit(t *testing.T) {
	f := newFake()
	f.users["ops"] = &user{name: "ops"}
	b := start(t, f)

	res := b.Get("/iam/user?name=ops")
	if consoletest.Find(res.Doc, consoletest.ByName("arnTyped")) != nil {
		t.Fatal("a whole list offers an ARN field")
	}

	for i := range 1001 {
		arn := fmt.Sprintf("arn:aws:iam::000000000000:policy/p%04d", i)
		f.managed[arn] = &managed{name: fmt.Sprintf("p%04d", i), doc: readDoc}
	}
	res = b.Get("/iam/user?name=ops")
	consoletest.RequireText(t, res, "The list holds the first 1000 managed policies only")
	if consoletest.Find(res.Doc, consoletest.ByName("arnTyped")) == nil {
		t.Fatal("a cut list offers no ARN field")
	}

	// A policy past the list is attached by its ARN.
	last := "arn:aws:iam::000000000000:policy/p1000"
	res = b.PostForm("/iam/user/attach", url.Values{"user": {"ops"}, "arnTyped": {last}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Attached "+last+" to ops.")
}
