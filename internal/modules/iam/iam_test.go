package iam_test

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
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/smithy-go"

	"tule.dev/console/internal/app"
	"tule.dev/console/internal/consoletest"
	consoleiam "tule.dev/console/internal/modules/iam"
)

type key struct {
	lastUsed time.Time
	id       string
	status   types.StatusType
}

type user struct {
	name string
	tags []types.Tag
	keys []*key
}

// fakeIAM is IAM's users and keys in memory.
type fakeIAM struct {
	users map[string]*user
	n     int
	mu    sync.Mutex
}

func newFake() *fakeIAM { return &fakeIAM{users: map[string]*user{}} }

func noSuch(what string) error {
	return &smithy.GenericAPIError{
		Code:    "NoSuchEntity",
		Message: "No IAM user is named " + what + ".",
	}
}

func (f *fakeIAM) find(name string) (*user, error) {
	u, ok := f.users[name]
	if !ok {
		return nil, noSuch(name)
	}
	return u, nil
}

func (f *fakeIAM) ListUsers(
	_ context.Context,
	in *iam.ListUsersInput,
	_ ...func(*iam.Options),
) (*iam.ListUsersOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	names := make([]string, 0, len(f.users))
	for n := range f.users {
		names = append(names, n)
	}
	sort.Strings(names)
	start := 0
	if in.Marker != nil {
		_, _ = fmt.Sscan(*in.Marker, &start)
	}
	out := &iam.ListUsersOutput{}
	end := min(len(names), start+int(*in.MaxItems))
	for _, n := range names[start:end] {
		out.Users = append(out.Users, types.User{
			UserName: aws.String(
				n,
			),
			Arn:        aws.String("arn:aws:iam::000000000000:user/" + n),
			Path:       aws.String("/"),
			UserId:     aws.String("AIDA" + n),
			CreateDate: aws.Time(time.Unix(0, 0)),
		})
	}
	if end < len(names) {
		out.IsTruncated, out.Marker = true, aws.String(fmt.Sprint(end))
	}
	return out, nil
}

func (f *fakeIAM) GetUser(
	_ context.Context,
	in *iam.GetUserInput,
	_ ...func(*iam.Options),
) (*iam.GetUserOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, err := f.find(*in.UserName)
	if err != nil {
		return nil, err
	}
	return &iam.GetUserOutput{User: &types.User{
		UserName: aws.String(
			u.name,
		),
		Arn:  aws.String("arn:aws:iam::000000000000:user/" + u.name),
		Path: aws.String("/"),
	}}, nil
}

func (f *fakeIAM) CreateUser(
	_ context.Context,
	in *iam.CreateUserInput,
	_ ...func(*iam.Options),
) (*iam.CreateUserOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.users[*in.UserName]; ok {
		return nil, &smithy.GenericAPIError{
			Code:    "EntityAlreadyExists",
			Message: "User with name " + *in.UserName + " already exists.",
		}
	}
	f.users[*in.UserName] = &user{name: *in.UserName}
	return &iam.CreateUserOutput{}, nil
}

func (f *fakeIAM) DeleteUser(
	_ context.Context,
	in *iam.DeleteUserInput,
	_ ...func(*iam.Options),
) (*iam.DeleteUserOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, err := f.find(*in.UserName)
	if err != nil {
		return nil, err
	}
	if len(u.keys) > 0 {
		return nil, &smithy.GenericAPIError{
			Code:    "DeleteConflict",
			Message: "Cannot delete entity, must delete access keys first.",
		}
	}
	delete(f.users, u.name)
	return &iam.DeleteUserOutput{}, nil
}

func (f *fakeIAM) ListAccessKeys(
	_ context.Context, in *iam.ListAccessKeysInput, _ ...func(*iam.Options),
) (*iam.ListAccessKeysOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, err := f.find(*in.UserName)
	if err != nil {
		return nil, err
	}
	out := &iam.ListAccessKeysOutput{}
	for _, k := range u.keys {
		out.AccessKeyMetadata = append(out.AccessKeyMetadata, types.AccessKeyMetadata{
			AccessKeyId: aws.String(
				k.id,
			),
			Status:     k.status,
			UserName:   aws.String(u.name),
			CreateDate: aws.Time(time.Unix(0, 0)),
		})
	}
	return out, nil
}

func (f *fakeIAM) CreateAccessKey(
	_ context.Context, in *iam.CreateAccessKeyInput, _ ...func(*iam.Options),
) (*iam.CreateAccessKeyOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, err := f.find(*in.UserName)
	if err != nil {
		return nil, err
	}
	f.n++
	id := fmt.Sprintf("AKIAFAKEKEY%09d", f.n)
	u.keys = append(u.keys, &key{id: id, status: types.StatusTypeActive})
	return &iam.CreateAccessKeyOutput{AccessKey: &types.AccessKey{
		AccessKeyId: aws.String(
			id,
		),
		SecretAccessKey: aws.String("secret-of-" + id),
		Status:          types.StatusTypeActive,
	}}, nil
}

func (f *fakeIAM) key(user, id string) (*user, *key, error) {
	u, err := f.find(user)
	if err != nil {
		return nil, nil, err
	}
	for _, k := range u.keys {
		if k.id == id {
			return u, k, nil
		}
	}
	return nil, nil, noSuch(id)
}

func (f *fakeIAM) UpdateAccessKey(
	_ context.Context, in *iam.UpdateAccessKeyInput, _ ...func(*iam.Options),
) (*iam.UpdateAccessKeyOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, k, err := f.key(*in.UserName, *in.AccessKeyId)
	if err != nil {
		return nil, err
	}
	k.status = in.Status
	return &iam.UpdateAccessKeyOutput{}, nil
}

func (f *fakeIAM) DeleteAccessKey(
	_ context.Context, in *iam.DeleteAccessKeyInput, _ ...func(*iam.Options),
) (*iam.DeleteAccessKeyOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, k, err := f.key(*in.UserName, *in.AccessKeyId)
	if err != nil {
		return nil, err
	}
	for i, x := range u.keys {
		if x == k {
			u.keys = append(u.keys[:i], u.keys[i+1:]...)
		}
	}
	return &iam.DeleteAccessKeyOutput{}, nil
}

func (f *fakeIAM) GetAccessKeyLastUsed(
	_ context.Context, in *iam.GetAccessKeyLastUsedInput, _ ...func(*iam.Options),
) (*iam.GetAccessKeyLastUsedOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, u := range f.users {
		for _, k := range u.keys {
			if k.id == *in.AccessKeyId {
				lu := &types.AccessKeyLastUsed{
					ServiceName: aws.String("N/A"),
					Region:      aws.String("N/A"),
				}
				if !k.lastUsed.IsZero() {
					lu = &types.AccessKeyLastUsed{
						LastUsedDate: aws.Time(
							k.lastUsed,
						),
						ServiceName: aws.String("s3"),
						Region:      aws.String("us-east-1"),
					}
				}
				return &iam.GetAccessKeyLastUsedOutput{AccessKeyLastUsed: lu}, nil
			}
		}
	}
	return nil, noSuch(*in.AccessKeyId)
}

func (f *fakeIAM) ListUserTags(
	_ context.Context,
	in *iam.ListUserTagsInput,
	_ ...func(*iam.Options),
) (*iam.ListUserTagsOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, err := f.find(*in.UserName)
	if err != nil {
		return nil, err
	}
	return &iam.ListUserTagsOutput{Tags: u.tags}, nil
}

func start(t *testing.T, f *fakeIAM) *consoletest.Browser {
	t.Helper()
	s := consoletest.Start(
		t,
		app.Overrides{IAM: func(aws.Credentials) consoleiam.API { return f }},
		nil,
		"iam",
	)
	b := s.Browser(t)
	b.SignIn(consoletest.KeyID, consoletest.Secret)
	return b
}

func TestUsersWithKeys(t *testing.T) {
	f := newFake()
	f.users["alice"] = &user{name: "alice", keys: []*key{
		{
			id:       "AKIAALICE00000000001",
			status:   types.StatusTypeActive,
			lastUsed: time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC),
		},
		{id: "AKIAALICE00000000002", status: types.StatusTypeInactive},
	}}
	f.users["bob"] = &user{name: "bob"}
	b := start(t, f)
	res := b.Get("/iam")
	consoletest.RequireStatus(t, res, http.StatusOK)
	consoletest.RequireText(t, res, "alice", "bob", "AKIAALICE00000000001", "Active", "Inactive",
		"last used 2026-11-01 10:00:00 UTC", "never used")
}

func TestUsersPage(t *testing.T) {
	f := newFake()
	for i := range 60 {
		n := fmt.Sprintf("user%02d", i)
		f.users[n] = &user{name: n}
	}
	b := start(t, f)
	res := b.Get("/iam")
	next := consoletest.Href(res.Doc, "Next page")
	if next == "" {
		t.Fatal("no next page with 60 users")
	}
	res = b.Get(next)
	consoletest.RequireText(t, res, "user59", "First page")
}

func TestUserLifecycle(t *testing.T) {
	f := newFake()
	b := start(t, f)
	b.Get("/iam")

	res := b.PostForm("/iam/users", url.Values{"name": {"carol"}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Created user carol.")

	// The new key's secret is in this answer only.
	res = b.PostForm("/iam/keys", url.Values{"user": {"carol"}})
	consoletest.RequireStatus(t, res, http.StatusOK)
	id := f.users["carol"].keys[0].id
	consoletest.RequireText(t, res, id, "secret-of-"+id, "only time the secret is shown")
	if res.Header.Get("Cache-Control") != "no-store" ||
		!strings.Contains(string(res.Body), `hx-history="false"`) {
		t.Fatal("the secret's page may be cached or kept in history")
	}
	page := b.Get("/iam/user?name=carol")
	if strings.Contains(string(page.Body), "secret-of-") {
		t.Fatal("the IAM user's page shows the key's secret")
	}

	res = b.PostForm(
		"/iam/keys/status",
		url.Values{"user": {"carol"}, "id": {id}, "status": {"Inactive"}},
	)
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Deactivated key "+id)
	if f.users["carol"].keys[0].status != types.StatusTypeInactive {
		t.Fatal("the key is still active")
	}
	res = b.PostForm(
		"/iam/keys/status",
		url.Values{"user": {"carol"}, "id": {id}, "status": {"Active"}},
	)
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Activated key "+id)
	res = b.PostForm(
		"/iam/keys/status",
		url.Values{"user": {"carol"}, "id": {id}, "status": {"Bogus"}},
	)
	consoletest.RequireFlash(t, b.Get(res.Location()), "error", "Active or Inactive")

	res = b.PostForm("/iam/users/delete", url.Values{"name": {"carol"}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "error", "must delete access keys first")

	res = b.PostForm("/iam/keys/delete", url.Values{"user": {"carol"}, "id": {id}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Deleted key "+id)

	res = b.PostForm("/iam/users/delete", url.Values{"name": {"carol"}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Deleted user carol.")
	if _, ok := f.users["carol"]; ok {
		t.Fatal("the IAM user was not deleted")
	}
}

func TestHostileUsersRenderInert(t *testing.T) {
	f := newFake()
	for i, h := range consoletest.Hostile {
		f.users[h] = &user{
			name: h, tags: []types.Tag{{Key: aws.String(h), Value: aws.String(h)}},
			keys: []*key{{id: fmt.Sprintf("%s-%d", h, i), status: types.StatusTypeActive}},
		}
	}
	b := start(t, f)
	res := b.Get("/iam")
	consoletest.RequireInert(t, res)
	consoletest.RequireText(t, res, consoletest.Hostile...)
	for _, h := range consoletest.Hostile {
		res = b.Get("/iam/user?name=" + url.QueryEscape(h))
		consoletest.RequireStatus(t, res, http.StatusOK)
		consoletest.RequireInert(t, res)
	}
	res = b.PostForm("/iam/keys", url.Values{"user": {consoletest.Hostile[0]}})
	consoletest.RequireInert(t, res)
}

// hollowIAM answers GetUser and CreateAccessKey without their User and
// AccessKey, as a faulty service could.
type hollowIAM struct{ *fakeIAM }

func (hollowIAM) GetUser(
	context.Context,
	*iam.GetUserInput,
	...func(*iam.Options),
) (*iam.GetUserOutput, error) {
	return &iam.GetUserOutput{}, nil
}

func (hollowIAM) CreateAccessKey(
	context.Context, *iam.CreateAccessKeyInput, ...func(*iam.Options),
) (*iam.CreateAccessKeyOutput, error) {
	return &iam.CreateAccessKeyOutput{}, nil
}

func TestHollowAnswersAreErrors(t *testing.T) {
	f := newFake()
	f.users["alice"] = &user{name: "alice"}
	s := consoletest.Start(
		t,
		app.Overrides{IAM: func(aws.Credentials) consoleiam.API { return hollowIAM{f} }},
		nil,
		"iam",
	)
	b := s.Browser(t)
	b.SignIn(consoletest.KeyID, consoletest.Secret)

	res := b.Get("/iam/user?name=alice")
	consoletest.RequireStatus(t, res, http.StatusBadGateway)
	consoletest.RequireText(t, res, "The service answered GetUser without its User.")

	b.Get("/iam")
	res = b.PostForm("/iam/keys", url.Values{"user": {"alice"}})
	consoletest.RequireStatus(t, res, http.StatusSeeOther)
	consoletest.RequireFlash(t, b.Get("/iam"), "error", "CreateAccessKey without its AccessKey")
}
