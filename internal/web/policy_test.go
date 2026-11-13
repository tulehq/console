package web_test

import (
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
