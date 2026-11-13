// Package secrets is the secret-store section: listing and searching
// secrets, a secret's metadata and versions with their labels, revealing a
// value only when asked, creating a secret, putting a new value, and
// deleting with a recovery window or restoring.
package secrets

import (
	"context"
	"encoding/base64"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/gasmod/gas"

	"tule.dev/console/internal/web"
)

// Key is the section's key, and Path the path its pages live under.
const (
	Key  = "secrets"
	Path = "/secrets"
)

const (
	moduleName = "tule/modules/secrets"
	// maxListed bounds how many secrets the list reads, as secret-store
	// filters nothing itself and the search runs over the whole list.
	maxListed = 5000
)

// API is the part of the Secrets Manager client the section calls;
// *secretsmanager.Client is one.
type API interface {
	ListSecrets(
		context.Context, *secretsmanager.ListSecretsInput, ...func(*secretsmanager.Options),
	) (*secretsmanager.ListSecretsOutput, error)
	DescribeSecret(
		context.Context, *secretsmanager.DescribeSecretInput, ...func(*secretsmanager.Options),
	) (*secretsmanager.DescribeSecretOutput, error)
	ListSecretVersionIds(
		context.Context, *secretsmanager.ListSecretVersionIdsInput, ...func(*secretsmanager.Options),
	) (*secretsmanager.ListSecretVersionIdsOutput, error)
	GetSecretValue(
		context.Context, *secretsmanager.GetSecretValueInput, ...func(*secretsmanager.Options),
	) (*secretsmanager.GetSecretValueOutput, error)
	CreateSecret(
		context.Context, *secretsmanager.CreateSecretInput, ...func(*secretsmanager.Options),
	) (*secretsmanager.CreateSecretOutput, error)
	PutSecretValue(
		context.Context, *secretsmanager.PutSecretValueInput, ...func(*secretsmanager.Options),
	) (*secretsmanager.PutSecretValueOutput, error)
	DeleteSecret(
		context.Context, *secretsmanager.DeleteSecretInput, ...func(*secretsmanager.Options),
	) (*secretsmanager.DeleteSecretOutput, error)
	RestoreSecret(
		context.Context, *secretsmanager.RestoreSecretInput, ...func(*secretsmanager.Options),
	) (*secretsmanager.RestoreSecretOutput, error)
}

// NewClient returns the client for a session's credentials.
type NewClient func(aws.Credentials) API

// Module serves the section.
type Module struct {
	router    *gas.Router
	render    *web.Renderer
	newClient NewClient
}

// NewModule returns the module. It registers its routes when the app
// initializes it.
func NewModule(router *gas.Router, render *web.Renderer, newClient NewClient) *Module {
	return &Module{router: router, render: render, newClient: newClient}
}

// Name identifies the module to gas.
func (m *Module) Name() string { return moduleName }

// Init registers the module's routes.
func (m *Module) Init(context.Context) error {
	m.router.Route(m, Path, func(g *gas.RouteGroup) {
		g.Get("/", m.list)
		g.Post("/", m.create)
		g.Get("/secret", m.secret)
		g.Post("/secret/reveal", m.reveal)
		g.Post("/secret/value", m.putValue)
		g.Post("/secret/delete", m.remove)
		g.Post("/secret/restore", m.restore)
	})
	return nil
}

// Close releases nothing; the module holds no resources of its own.
func (m *Module) Close(context.Context) error { return nil }

func (m *Module) client(c gas.Context) API {
	return m.newClient(web.FromContext(c).Credentials())
}

func secretLink(id string) string {
	return web.Link(Path+"/secret", "id", id)
}

// Summary is a secret in the list.
type Summary struct {
	Changed     time.Time
	Deleted     time.Time
	Name        string
	Description string
	Link        string
}

type listView struct {
	Query     string
	Secrets   []Summary
	Total     int
	Truncated bool
}

func (m *Module) list(c gas.Context) error {
	q := strings.TrimSpace(c.Query("q"))
	v := listView{Query: q}
	api := m.client(c)
	in := &secretsmanager.ListSecretsInput{
		MaxResults:             aws.Int32(100),
		IncludePlannedDeletion: aws.Bool(true),
	}
	for {
		out, err := api.ListSecrets(c, in)
		if err != nil {
			return m.render.Fail(c, Key, "Secrets", err)
		}
		for _, s := range out.SecretList {
			v.Total++
			name, desc := aws.ToString(s.Name), aws.ToString(s.Description)
			if !matches(q, name, desc) {
				continue
			}
			v.Secrets = append(v.Secrets, Summary{
				Name:        name,
				Description: desc,
				Changed:     aws.ToTime(s.LastChangedDate),
				Deleted:     aws.ToTime(s.DeletedDate),
				Link:        secretLink(name),
			})
		}
		if aws.ToString(out.NextToken) == "" {
			break
		}
		if v.Total >= maxListed {
			v.Truncated = true
			break
		}
		in.NextToken = out.NextToken
	}
	return m.render.Render(c, web.Page{
		Name: "secrets/list", Title: "Secrets", Section: Key, Data: v, Block: "results",
	})
}

// matches reports whether every word of q is in the name or the
// description, without regard to case.
func matches(q, name, desc string) bool {
	hay := strings.ToLower(name + "\n" + desc)
	for w := range strings.FieldsSeq(strings.ToLower(q)) {
		if !strings.Contains(hay, w) {
			return false
		}
	}
	return true
}

// Version is a version of a secret, with its staging labels.
type Version struct {
	Created time.Time
	ID      string
	Stages  []string
}

// Tag is a tag of a secret.
type Tag struct {
	Key   string
	Value string
}

// Revealed is a value revealed on request.
type Revealed struct {
	VersionID string
	Text      string
	Stages    []string
	Binary    bool
}

type secretView struct {
	Created      time.Time
	Changed      time.Time
	Accessed     time.Time
	Deleted      time.Time
	Revealed     *Revealed
	Name         string
	ARN          string
	Description  string
	KmsKeyID     string
	Tags         []Tag
	Versions     []Version
	RecoveryDays int
}

func (m *Module) describe(c gas.Context, id string) (secretView, error) {
	api := m.client(c)
	d, err := api.DescribeSecret(c, &secretsmanager.DescribeSecretInput{SecretId: aws.String(id)})
	if err != nil {
		return secretView{}, err
	}
	v := secretView{
		Name:         aws.ToString(d.Name),
		ARN:          aws.ToString(d.ARN),
		Description:  aws.ToString(d.Description),
		KmsKeyID:     aws.ToString(d.KmsKeyId),
		Created:      aws.ToTime(d.CreatedDate),
		Changed:      aws.ToTime(d.LastChangedDate),
		Accessed:     aws.ToTime(d.LastAccessedDate),
		Deleted:      aws.ToTime(d.DeletedDate),
		RecoveryDays: 30,
	}
	for _, t := range d.Tags {
		v.Tags = append(v.Tags, Tag{Key: aws.ToString(t.Key), Value: aws.ToString(t.Value)})
	}
	if v.Deleted.IsZero() {
		// A secret scheduled for deletion answers nothing but describe
		// and restore, so it has no versions to list.
		in := &secretsmanager.ListSecretVersionIdsInput{
			SecretId:   aws.String(id),
			MaxResults: aws.Int32(100),
		}
		for {
			out, lerr := api.ListSecretVersionIds(c, in)
			if lerr != nil {
				return secretView{}, lerr
			}
			for _, ver := range out.Versions {
				v.Versions = append(v.Versions, Version{
					ID:      aws.ToString(ver.VersionId),
					Stages:  ver.VersionStages,
					Created: aws.ToTime(ver.CreatedDate),
				})
			}
			if aws.ToString(out.NextToken) == "" {
				break
			}
			in.NextToken = out.NextToken
		}
	} else {
		for vid, stages := range d.VersionIdsToStages {
			v.Versions = append(v.Versions, Version{ID: vid, Stages: stages})
		}
		sort.Slice(v.Versions, func(i, j int) bool { return v.Versions[i].ID < v.Versions[j].ID })
	}
	return v, nil
}

func (m *Module) secret(c gas.Context) error {
	id := c.Query("id")
	v, err := m.describe(c, id)
	if err != nil {
		return m.render.Fail(c, Key, id, err)
	}
	return m.render.Render(
		c,
		web.Page{Name: "secrets/secret", Title: v.Name, Section: Key, Data: v},
	)
}

// reveal answers a version's value: the value block alone to an HTMX
// request, and the secret's page with it shown to a plain form post. The
// value is in that one response only, which is never cached.
func (m *Module) reveal(c gas.Context) error {
	form := c.Request().PostForm
	id, versionID := form.Get("id"), form.Get("versionId")
	in := &secretsmanager.GetSecretValueInput{SecretId: aws.String(id)}
	if versionID != "" {
		in.VersionId = aws.String(versionID)
	}
	out, err := m.client(c).GetSecretValue(c, in)
	if err != nil {
		return m.render.Fail(c, Key, id, err)
	}
	r := &Revealed{VersionID: aws.ToString(out.VersionId), Stages: out.VersionStages}
	if out.SecretString != nil {
		r.Text = *out.SecretString
	} else {
		r.Binary = true
		r.Text = base64.StdEncoding.EncodeToString(out.SecretBinary)
	}

	var v secretView
	if web.IsHTMX(c.Request()) {
		v = secretView{Name: id}
	} else if v, err = m.describe(c, id); err != nil {
		return m.render.Fail(c, Key, id, err)
	}
	v.Revealed = r
	return m.render.Render(c, web.Page{
		Name: "secrets/secret", Title: v.Name, Section: Key, Data: v, Block: "value",
	})
}

func (m *Module) create(c gas.Context) error {
	form := c.Request().PostForm
	name := strings.TrimSpace(form.Get("name"))
	if name == "" {
		return web.Invalid(c, Path, "Enter a name for the secret.")
	}
	in := &secretsmanager.CreateSecretInput{
		Name:         aws.String(name),
		SecretString: aws.String(form.Get("value")),
	}
	if d := strings.TrimSpace(form.Get("description")); d != "" {
		in.Description = aws.String(d)
	}
	if _, err := m.client(c).CreateSecret(c, in); err != nil {
		return web.Failed(c, Path, "Secret "+name+" was not created", err)
	}
	return web.Done(c, secretLink(name), "Created secret "+name+".")
}

func (m *Module) putValue(c gas.Context) error {
	form := c.Request().PostForm
	id := form.Get("id")
	out, err := m.client(c).PutSecretValue(c, &secretsmanager.PutSecretValueInput{
		SecretId:     aws.String(id),
		SecretString: aws.String(form.Get("value")),
	})
	if err != nil {
		return web.Failed(c, secretLink(id), "The new value was not stored", err)
	}
	return web.Done(
		c,
		secretLink(id),
		"Stored a new value as version "+aws.ToString(out.VersionId)+".",
	)
}

func (m *Module) remove(c gas.Context) error {
	form := c.Request().PostForm
	id := form.Get("id")
	in := &secretsmanager.DeleteSecretInput{SecretId: aws.String(id)}
	if form.Get("force") == "on" {
		in.ForceDeleteWithoutRecovery = aws.Bool(true)
	} else {
		days, err := strconv.ParseInt(form.Get("days"), 10, 64)
		if err != nil || days < 7 || days > 30 {
			return web.Invalid(c, secretLink(id), "The recovery window is 7 to 30 days.")
		}
		in.RecoveryWindowInDays = aws.Int64(days)
	}
	out, err := m.client(c).DeleteSecret(c, in)
	if err != nil {
		return web.Failed(c, secretLink(id), "Secret "+id+" was not deleted", err)
	}
	if aws.ToBool(in.ForceDeleteWithoutRecovery) {
		return web.Done(c, Path, "Deleted secret "+id+" without recovery.")
	}
	return web.Done(c, secretLink(id), fmt.Sprintf("Secret %s is scheduled for deletion on %s.",
		id, web.FormatTime(aws.ToTime(out.DeletionDate))))
}

func (m *Module) restore(c gas.Context) error {
	id := c.Request().PostForm.Get("id")
	if _, err := m.client(c).
		RestoreSecret(c, &secretsmanager.RestoreSecretInput{SecretId: aws.String(id)}); err != nil {
		return web.Failed(c, secretLink(id), "Secret "+id+" was not restored", err)
	}
	return web.Done(c, secretLink(id), "Restored secret "+id+".")
}
