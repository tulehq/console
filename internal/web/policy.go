package web

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
)

// Field is a hidden field of a form, naming what the form acts on.
type Field struct {
	Name  string
	Value string
}

// Policy is a resource-based policy as a page's Policy section shows it,
// with the forms that save and delete it.
type Policy struct {
	// ReadErr is why the policy could not be read, such as the service's
	// AccessDenied; the section shows it in place of the form.
	ReadErr *Failure
	// Error is why the last save or delete was refused, shown next to the
	// form, whose Document is then the one that was sent.
	Error *Failure
	// Validation is what a check of Document found, for a service that
	// checks a policy without storing it.
	Validation *Validation
	// ID tells the section's elements apart from another's on the page.
	ID string
	// Name is the policy's name, for a resource that holds several.
	Name string
	// Action saves the document, DeleteAction deletes the policy, and
	// ValidateAction, when set, checks the document without saving it.
	Action         string
	DeleteAction   string
	ValidateAction string
	// Document is the stored policy, indented, or what was typed.
	Document string
	// Current is the stored policy, indented, when a save was refused
	// because it changed since the page was read.
	Current string
	// Placeholder is an example document for an empty form.
	Placeholder string
	// RemoveAction removes one of Statements by its Sid, sent as
	// RemoveField.
	RemoveAction string
	RemoveField  string
	Fields       []Field
	// Statements are Document's statements, for a resource whose
	// statements can be removed one at a time.
	Statements []Statement
	// Exists is set when the resource has the policy stored.
	Exists bool
	// Unknown is set when a refused save is shown and the policy could not
	// be read again, so whether one is stored is not known.
	Unknown bool
	// Named is set for a resource that holds several policies by name;
	// a form of a policy that does not exist yet then asks for its name.
	Named bool
	// BlockPublicBox shows the form's "block public policy" box, checked
	// when BlockPublic is set.
	BlockPublicBox bool
	BlockPublic    bool
}

// Validation is the outcome of checking a policy without storing it.
type Validation struct {
	Findings []Finding
	Passed   bool
}

// Finding is one thing a policy check found.
type Finding struct {
	Check   string
	Message string
}

// ReadFailure describes err, a failed read of a policy, for the section to
// show in its place.
func ReadFailure(err error) *Failure {
	f := Describe(err)
	return &f
}

// FormatJSON returns doc indented, or as it is when it is not JSON, so
// nothing of it is lost.
func FormatJSON(doc string) string {
	var buf bytes.Buffer
	if err := json.Indent(&buf, []byte(doc), "", "  "); err != nil {
		return doc
	}
	return buf.String()
}

// Statement is a statement of a policy as a page lists it: each element
// as compact JSON, or "" when the statement has none.
type Statement struct {
	Sid       string
	Effect    string
	Principal string
	Action    string
	Resource  string
	Condition string
}

// Statements returns the statements of the policy doc, in order, or nil
// when doc is not a policy the console can read; Statement may be one
// object or an array of them.
func Statements(doc string) []Statement {
	var p struct {
		Statement json.RawMessage
	}
	if err := json.Unmarshal([]byte(doc), &p); err != nil || len(p.Statement) == 0 {
		return nil
	}
	var raw []map[string]json.RawMessage
	if err := json.Unmarshal(p.Statement, &raw); err != nil {
		var one map[string]json.RawMessage
		if err = json.Unmarshal(p.Statement, &one); err != nil {
			return nil
		}
		raw = []map[string]json.RawMessage{one}
	}
	out := make([]Statement, 0, len(raw))
	for _, s := range raw {
		out = append(out, Statement{
			Sid:       jsonString(s["Sid"]),
			Effect:    jsonString(s["Effect"]),
			Principal: compact(s["Principal"], s["NotPrincipal"], "not "),
			Action:    compact(s["Action"], s["NotAction"], "not "),
			Resource:  compact(s["Resource"], s["NotResource"], "not "),
			Condition: compact(s["Condition"], nil, ""),
		})
	}
	return out
}

// jsonString returns raw as the string it holds, or as compact JSON when
// it holds something else.
func jsonString(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return compact(raw, nil, "")
}

// compact returns raw as compact JSON, a string as its text, or, when raw
// is empty, negated with prefix, and "" when both are empty.
func compact(raw, negated json.RawMessage, prefix string) string {
	if len(raw) == 0 {
		if len(negated) == 0 {
			return ""
		}
		return prefix + compact(negated, nil, "")
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return strings.TrimSpace(string(raw))
	}
	return buf.String()
}

// Refuse makes the section show err, a refused save or delete, next to its
// form, with doc in the form as it was sent, and returns the status to
// answer with. The form is shown even when the policy could not be read,
// so what was typed is not lost.
func (p *Policy) Refuse(doc string, err error) int {
	f := Describe(err)
	if p.ReadErr != nil {
		p.Unknown = true
	}
	if errors.As(err, new(*ChangedError)) && p.Exists {
		p.Current = p.Document
	}
	p.ReadErr, p.Error, p.Document = nil, &f, doc
	return f.Status
}

// LoadedField is the hidden field that carries the version of the policy a
// page was read with.
const LoadedField = "loaded"

// PolicyVersion is the version of a stored policy doc a form sends back as
// LoadedField: a hash of it, or "" for no policy.
func PolicyVersion(doc string) string {
	if doc == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(doc))
	return hex.EncodeToString(sum[:])
}

// ChangedError is a save refused because the policy stored now is not the
// one the page was read with, so the save would lose a change made since.
type ChangedError struct{}

func (*ChangedError) Error() string {
	return "The policy changed since the page was loaded, so it was not saved. " +
		"The document you sent is kept below; compare it with the stored policy and save again."
}

// Unchanged returns a ChangedError unless stored, the policy as it is now
// ("" for none), is the version loaded that the form sent.
func Unchanged(loaded, stored string) error {
	if PolicyVersion(stored) != loaded {
		return &ChangedError{}
	}
	return nil
}
