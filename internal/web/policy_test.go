package web_test

import (
	"net/http"
	"reflect"
	"testing"

	"tule.dev/console/internal/web"
)

func TestStatements(t *testing.T) {
	doc := `{"Version":"2012-10-17","Statement":[` +
		`{"Sid":"a","Effect":"Allow","Principal":"*","Action":["s3:GetObject", "s3:PutObject"],` +
		`"Resource":"arn:aws:s3:::b/*","Condition":{"Bool":{"aws:SecureTransport":"true"}}},` +
		`{"Effect":"Deny","NotPrincipal":{"AWS":"111122223333"},"NotAction":"s3:*","Resource":"*"}]}`
	want := []web.Statement{
		{
			Sid: "a", Effect: "Allow", Principal: "*", Action: `["s3:GetObject","s3:PutObject"]`,
			Resource: "arn:aws:s3:::b/*", Condition: `{"Bool":{"aws:SecureTransport":"true"}}`,
		},
		{
			Effect:    "Deny",
			Principal: `not {"AWS":"111122223333"}`,
			Action:    "not s3:*",
			Resource:  "*",
		},
	}
	if got := web.Statements(doc); !reflect.DeepEqual(got, want) {
		t.Fatalf("Statements:\n got %+v\nwant %+v", got, want)
	}
	one := `{"Statement":{"Sid":"x","Effect":"Allow"}}`
	if got := web.Statements(one); len(got) != 1 || got[0].Sid != "x" {
		t.Fatalf("a single statement object: %+v", got)
	}
	for _, bad := range []string{"", "not json", `{"Statement":"x"}`, `{"Version":"2012-10-17"}`} {
		if got := web.Statements(bad); got != nil {
			t.Fatalf("Statements(%q) = %+v, want nil", bad, got)
		}
	}
}

func TestFormatJSON(t *testing.T) {
	if got := web.FormatJSON(`{"a":[1]}`); got != "{\n  \"a\": [\n    1\n  ]\n}" {
		t.Fatalf("FormatJSON: %q", got)
	}
	if got := web.FormatJSON("{not json"); got != "{not json" {
		t.Fatalf("FormatJSON of a non-JSON document: %q", got)
	}
}

func TestUnchanged(t *testing.T) {
	doc := `{"Statement":[]}`
	if web.PolicyVersion("") != "" || web.PolicyVersion(doc) == "" {
		t.Fatal("a policy's version must be empty for none only")
	}
	if err := web.Unchanged(web.PolicyVersion(doc), doc); err != nil {
		t.Fatalf("the loaded policy: %v", err)
	}
	if err := web.Unchanged("", ""); err != nil {
		t.Fatalf("no policy loaded, none stored: %v", err)
	}
	for _, c := range []struct{ loaded, stored string }{
		{"", doc}, {web.PolicyVersion(doc), ""}, {web.PolicyVersion(doc), doc + " "},
	} {
		err := web.Unchanged(c.loaded, c.stored)
		if f := web.Describe(err); f.Status != http.StatusConflict {
			t.Fatalf(
				"Unchanged(%q, %q) = %v, status %d, want 409",
				c.loaded,
				c.stored,
				err,
				f.Status,
			)
		}
	}
}
