package secrets_test

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/smithy-go"

	"tule.dev/console/internal/app"
	"tule.dev/console/internal/consoletest"
	"tule.dev/console/internal/modules/secrets"
)

type version struct {
	id     string
	value  string
	stages []string
}

type secret struct {
	deleted     time.Time
	name        string
	description string
	versions    []version
}

// fakeSM is a Secrets Manager in memory.
type fakeSM struct {
	secrets map[string]*secret
	listIn  []*secretsmanager.ListSecretsInput
	reads   int
	mu      sync.Mutex
}

func newFake() *fakeSM { return &fakeSM{secrets: map[string]*secret{}} }

func (f *fakeSM) add(name, desc, value string) {
	f.secrets[name] = &secret{name: name, description: desc, versions: []version{
		{id: "v1-" + name, value: value, stages: []string{"AWSCURRENT"}},
	}}
}

func notFound(id string) error {
	return &smithy.GenericAPIError{
		Code:    "ResourceNotFoundException",
		Message: "Secrets Manager can't find " + id,
	}
}

func (f *fakeSM) find(id string) (*secret, error) {
	s, ok := f.secrets[id]
	if !ok {
		return nil, notFound(id)
	}
	return s, nil
}

func (f *fakeSM) ListSecrets(
	_ context.Context, in *secretsmanager.ListSecretsInput, _ ...func(*secretsmanager.Options),
) (*secretsmanager.ListSecretsOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listIn = append(f.listIn, in)
	names := make([]string, 0, len(f.secrets))
	for n := range f.secrets {
		names = append(names, n)
	}
	sort.Strings(names)
	// Two per page, so the console must follow the token.
	start := 0
	if in.NextToken != nil {
		_, _ = fmt.Sscan(*in.NextToken, &start)
	}
	out := &secretsmanager.ListSecretsOutput{}
	for i := start; i < len(names) && i < start+2; i++ {
		s := f.secrets[names[i]]
		e := types.SecretListEntry{Name: aws.String(s.name), Description: aws.String(s.description)}
		if !s.deleted.IsZero() {
			e.DeletedDate = aws.Time(s.deleted)
		}
		out.SecretList = append(out.SecretList, e)
	}
	if start+2 < len(names) {
		out.NextToken = aws.String(fmt.Sprint(start + 2))
	}
	return out, nil
}

func (f *fakeSM) DescribeSecret(
	_ context.Context, in *secretsmanager.DescribeSecretInput, _ ...func(*secretsmanager.Options),
) (*secretsmanager.DescribeSecretOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, err := f.find(*in.SecretId)
	if err != nil {
		return nil, err
	}
	out := &secretsmanager.DescribeSecretOutput{
		Name: aws.String(
			s.name,
		),
		ARN: aws.String(
			"arn:aws:secretsmanager:us-east-1:000000000000:secret:" + s.name,
		),
		Description:        aws.String(s.description),
		VersionIdsToStages: map[string][]string{},
	}
	if !s.deleted.IsZero() {
		out.DeletedDate = aws.Time(s.deleted)
	}
	for _, v := range s.versions {
		out.VersionIdsToStages[v.id] = v.stages
	}
	return out, nil
}

//nolint:revive // the SDK's method name
func (f *fakeSM) ListSecretVersionIds(
	_ context.Context,
	in *secretsmanager.ListSecretVersionIdsInput,
	_ ...func(*secretsmanager.Options),
) (*secretsmanager.ListSecretVersionIdsOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, err := f.find(*in.SecretId)
	if err != nil {
		return nil, err
	}
	out := &secretsmanager.ListSecretVersionIdsOutput{}
	for _, v := range s.versions {
		out.Versions = append(
			out.Versions,
			types.SecretVersionsListEntry{VersionId: aws.String(v.id), VersionStages: v.stages},
		)
	}
	return out, nil
}

func (f *fakeSM) GetSecretValue(
	_ context.Context, in *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options),
) (*secretsmanager.GetSecretValueOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	s, err := f.find(*in.SecretId)
	if err != nil {
		return nil, err
	}
	for _, v := range s.versions {
		if (in.VersionId != nil && *in.VersionId == v.id) ||
			(in.VersionId == nil && v.stages[0] == "AWSCURRENT") {
			return &secretsmanager.GetSecretValueOutput{
				VersionId: aws.String(
					v.id,
				),
				SecretString:  aws.String(v.value),
				VersionStages: v.stages,
			}, nil
		}
	}
	return nil, notFound(*in.SecretId)
}

func (f *fakeSM) CreateSecret(
	_ context.Context, in *secretsmanager.CreateSecretInput, _ ...func(*secretsmanager.Options),
) (*secretsmanager.CreateSecretOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.add(*in.Name, aws.ToString(in.Description), aws.ToString(in.SecretString))
	return &secretsmanager.CreateSecretOutput{Name: in.Name}, nil
}

func (f *fakeSM) PutSecretValue(
	_ context.Context, in *secretsmanager.PutSecretValueInput, _ ...func(*secretsmanager.Options),
) (*secretsmanager.PutSecretValueOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, err := f.find(*in.SecretId)
	if err != nil {
		return nil, err
	}
	for i := range s.versions {
		s.versions[i].stages = []string{"AWSPREVIOUS"}
	}
	id := fmt.Sprintf("v%d-%s", len(s.versions)+1, s.name)
	s.versions = append(
		s.versions,
		version{id: id, value: *in.SecretString, stages: []string{"AWSCURRENT"}},
	)
	return &secretsmanager.PutSecretValueOutput{VersionId: aws.String(id)}, nil
}

func (f *fakeSM) DeleteSecret(
	_ context.Context, in *secretsmanager.DeleteSecretInput, _ ...func(*secretsmanager.Options),
) (*secretsmanager.DeleteSecretOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, err := f.find(*in.SecretId)
	if err != nil {
		return nil, err
	}
	if aws.ToBool(in.ForceDeleteWithoutRecovery) {
		delete(f.secrets, s.name)
		return &secretsmanager.DeleteSecretOutput{}, nil
	}
	s.deleted = time.Now().Add(time.Duration(*in.RecoveryWindowInDays) * 24 * time.Hour)
	return &secretsmanager.DeleteSecretOutput{DeletionDate: aws.Time(s.deleted)}, nil
}

func (f *fakeSM) RestoreSecret(
	_ context.Context, in *secretsmanager.RestoreSecretInput, _ ...func(*secretsmanager.Options),
) (*secretsmanager.RestoreSecretOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, err := f.find(*in.SecretId)
	if err != nil {
		return nil, err
	}
	s.deleted = time.Time{}
	return &secretsmanager.RestoreSecretOutput{}, nil
}

func start(t *testing.T, f *fakeSM) *consoletest.Browser {
	t.Helper()
	s := consoletest.Start(
		t,
		app.Overrides{SecretStore: func(aws.Credentials) secrets.API { return f }},
		nil,
		"secrets",
	)
	b := s.Browser(t)
	b.SignIn(consoletest.KeyID, consoletest.Secret)
	return b
}

func TestListAndSearch(t *testing.T) {
	f := newFake()
	f.add("prod/db", "database password", "hunter2")
	f.add("prod/api", "the API key", "k")
	f.add("dev/db", "local database", "d")
	b := start(t, f)

	res := b.Get("/secrets")
	consoletest.RequireStatus(t, res, http.StatusOK)
	consoletest.RequireText(t, res, "prod/db", "prod/api", "dev/db", "3 of 3 secrets")
	if strings.Contains(string(res.Body), "hunter2") {
		t.Fatal("the list shows a value")
	}
	if !aws.ToBool(f.listIn[0].IncludePlannedDeletion) {
		t.Fatal("the list leaves out secrets scheduled for deletion")
	}

	res = b.HTMX("/secrets?q=database+prod")
	consoletest.RequireStatus(t, res, http.StatusOK)
	if strings.Contains(string(res.Body), "<html") {
		t.Fatal("an HTMX search answered the whole page")
	}
	consoletest.RequireText(t, res, "prod/db", "1 of 3 secrets")
	if strings.Contains(consoletest.Text(res.Doc), "dev/db") {
		t.Fatal("the search kept a secret that does not match every word")
	}
}

func TestValueOnlyOnReveal(t *testing.T) {
	f := newFake()
	f.add("prod/db", "", "hunter2")
	b := start(t, f)

	res := b.Get("/secrets/secret?id=prod%2Fdb")
	consoletest.RequireStatus(t, res, http.StatusOK)
	consoletest.RequireText(t, res, "AWSCURRENT", "v1-prod/db", "Reveal current value")
	if strings.Contains(string(res.Body), "hunter2") || f.reads != 0 {
		t.Fatal("the page read or showed the value before it was asked to")
	}

	// A plain form post answers the page with the value.
	res = b.PostForm("/secrets/secret/reveal", url.Values{"id": {"prod/db"}})
	consoletest.RequireStatus(t, res, http.StatusOK)
	consoletest.RequireText(t, res, "hunter2", "AWSCURRENT")
	if res.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("a revealed value may be cached")
	}

	// HTMX gets the value block alone.
	res = b.HTMXPost(
		"/secrets/secret/reveal",
		url.Values{"id": {"prod/db"}, "versionId": {"v1-prod/db"}},
	)
	consoletest.RequireStatus(t, res, http.StatusOK)
	if strings.Contains(string(res.Body), "<h1") {
		t.Fatal("the HTMX reveal answered more than the value")
	}
	consoletest.RequireText(t, res, "hunter2")

	// The reveal is a state-changing request: it needs the token.
	res = b.PostForm("/secrets/secret/reveal", url.Values{"id": {"prod/db"}, "_csrf": {"x"}})
	consoletest.RequireStatus(t, res, http.StatusForbidden)
}

func TestCreatePutDeleteRestore(t *testing.T) {
	f := newFake()
	b := start(t, f)
	b.Get("/secrets")

	res := b.PostForm(
		"/secrets",
		url.Values{"name": {"app/token"}, "description": {"d"}, "value": {"one"}},
	)
	consoletest.RequireStatus(t, res, http.StatusSeeOther)
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Created secret app/token.")

	res = b.PostForm("/secrets/secret/value", url.Values{"id": {"app/token"}, "value": {"two"}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "v2-app/token")
	if v := f.secrets["app/token"].versions; len(v) != 2 || v[1].value != "two" {
		t.Fatalf("versions %+v", v)
	}

	res = b.PostForm("/secrets/secret/delete", url.Values{"id": {"app/token"}, "days": {"3"}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "error", "7 to 30 days")

	res = b.PostForm("/secrets/secret/delete", url.Values{"id": {"app/token"}, "days": {"7"}})
	page := b.Get(res.Location())
	consoletest.RequireFlash(t, page, "ok", "scheduled for deletion")
	consoletest.RequireText(t, page, "Restore secret")

	res = b.PostForm("/secrets/secret/restore", url.Values{"id": {"app/token"}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Restored secret app/token.")
	if !f.secrets["app/token"].deleted.IsZero() {
		t.Fatal("the secret is still scheduled for deletion")
	}

	res = b.PostForm("/secrets/secret/delete", url.Values{"id": {"app/token"}, "force": {"on"}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "without recovery")
	if _, ok := f.secrets["app/token"]; ok {
		t.Fatal("the secret was not deleted")
	}
}

func TestMissingSecret(t *testing.T) {
	b := start(t, newFake())
	res := b.Get("/secrets/secret?id=nope")
	consoletest.RequireText(t, res, "ResourceNotFoundException")
}

func TestHostileSecretsRenderInert(t *testing.T) {
	f := newFake()
	for _, h := range consoletest.Hostile {
		f.add(h, h, h)
	}
	b := start(t, f)
	res := b.Get("/secrets")
	consoletest.RequireInert(t, res)
	consoletest.RequireText(t, res, consoletest.Hostile...)
	for _, h := range consoletest.Hostile {
		res = b.Get("/secrets/secret?id=" + url.QueryEscape(h))
		consoletest.RequireStatus(t, res, http.StatusOK)
		consoletest.RequireInert(t, res)
		res = b.PostForm("/secrets/secret/reveal", url.Values{"id": {h}})
		consoletest.RequireInert(t, res)
		consoletest.RequireText(t, res, h)
	}
}
