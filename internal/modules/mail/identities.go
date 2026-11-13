package mail

import (
	"context"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sesv2/types"
	"github.com/gasmod/gas"

	"tule.dev/console/internal/web"
)

// SES is the part of the SES v2 client the section calls; *sesv2.Client
// is one.
type SES interface {
	ListEmailIdentities(
		context.Context, *sesv2.ListEmailIdentitiesInput, ...func(*sesv2.Options),
	) (*sesv2.ListEmailIdentitiesOutput, error)
	GetEmailIdentity(
		context.Context, *sesv2.GetEmailIdentityInput, ...func(*sesv2.Options),
	) (*sesv2.GetEmailIdentityOutput, error)
	GetEmailIdentityPolicies(
		context.Context, *sesv2.GetEmailIdentityPoliciesInput, ...func(*sesv2.Options),
	) (*sesv2.GetEmailIdentityPoliciesOutput, error)
	CreateEmailIdentityPolicy(
		context.Context, *sesv2.CreateEmailIdentityPolicyInput, ...func(*sesv2.Options),
	) (*sesv2.CreateEmailIdentityPolicyOutput, error)
	UpdateEmailIdentityPolicy(
		context.Context, *sesv2.UpdateEmailIdentityPolicyInput, ...func(*sesv2.Options),
	) (*sesv2.UpdateEmailIdentityPolicyOutput, error)
	DeleteEmailIdentityPolicy(
		context.Context, *sesv2.DeleteEmailIdentityPolicyInput, ...func(*sesv2.Options),
	) (*sesv2.DeleteEmailIdentityPolicyOutput, error)
}

// maxIdentities bounds how many identities the list reads.
const maxIdentities = 1000

func identityLink(name string) string {
	return web.Link(Path+"/identity", "name", name)
}

// IdentityRow is an email identity in the list.
type IdentityRow struct {
	Name           string
	Link           string
	Type           string
	Status         string
	SendingEnabled bool
}

type identitiesView struct {
	Identities []IdentityRow
	Truncated  bool
}

func (m *Module) identities(c gas.Context) error {
	v := identitiesView{}
	in := &sesv2.ListEmailIdentitiesInput{PageSize: aws.Int32(100)}
	for {
		out, err := m.ses(c).ListEmailIdentities(c, in)
		if err != nil {
			return m.render.Fail(c, Key, "Identities", err)
		}
		for _, id := range out.EmailIdentities {
			name := aws.ToString(id.IdentityName)
			v.Identities = append(v.Identities, IdentityRow{
				Name:           name,
				Link:           identityLink(name),
				Type:           string(id.IdentityType),
				Status:         string(id.VerificationStatus),
				SendingEnabled: id.SendingEnabled,
			})
		}
		if aws.ToString(out.NextToken) == "" {
			break
		}
		if len(v.Identities) >= maxIdentities {
			v.Truncated = true
			break
		}
		in.NextToken = out.NextToken
	}
	return m.render.Render(c, web.Page{
		Name: "mail/identities", Title: "Identities", Section: Key, Data: v,
	})
}

// identityView is an email identity's page: its details and its sending
// authorization policies, each in a form of its own, and a form for a new
// one. PoliciesErr is why the policies could not be read, shown in their
// place.
type identityView struct {
	PoliciesErr        *web.Failure
	New                *web.Policy
	Name               string
	Type               string
	Status             string
	ConfigurationSet   string
	Policies           []*web.Policy
	Tags               []types.Tag
	VerifiedForSending bool
}

// policyExample is the example a new sending authorization policy's form
// shows.
const policyExample = `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SendFromPartner",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::111122223333:root"},
      "Action": ["ses:SendEmail", "ses:SendRawEmail"],
      "Resource": "IDENTITY"
    }
  ]
}`

// identityARN is the ARN of the identity name, as the policies of the
// signed-in principal's account name it, or "" when the console does not
// know the account.
func (m *Module) identityARN(c gas.Context, name string) string {
	account := web.FromContext(c).Principal().Account
	s, ok := m.render.Section(Key)
	if account == "" || !ok {
		return ""
	}
	return "arn:aws:ses:" + s.Endpoint.Region + ":" + account + ":identity/" + name
}

func (m *Module) loadIdentity(c gas.Context, name string) (identityView, error) {
	api := m.ses(c)
	out, err := api.GetEmailIdentity(c, &sesv2.GetEmailIdentityInput{
		EmailIdentity: aws.String(name),
	})
	if err != nil {
		return identityView{}, err
	}
	v := identityView{
		Name:               name,
		Type:               string(out.IdentityType),
		Status:             string(out.VerificationStatus),
		VerifiedForSending: out.VerifiedForSendingStatus,
		ConfigurationSet:   aws.ToString(out.ConfigurationSetName),
		Tags:               out.Tags,
	}
	resource := m.identityARN(c, name)
	if resource == "" {
		resource = "arn:aws:ses:REGION:ACCOUNT:identity/" + name
	}
	v.New = m.namedPolicy(name, "", "")
	v.New.ID, v.New.Placeholder = "policy-new", strings.ReplaceAll(
		policyExample,
		"IDENTITY",
		resource,
	)

	// The policies are their own action, so a principal that may read the
	// identity but not its policies is shown why in their place.
	pols, err := api.GetEmailIdentityPolicies(c, &sesv2.GetEmailIdentityPoliciesInput{
		EmailIdentity: aws.String(name),
	})
	if err != nil {
		v.PoliciesErr = web.ReadFailure(err)
		return v, nil
	}
	names := make([]string, 0, len(pols.Policies))
	for n := range pols.Policies {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		p := m.namedPolicy(name, n, web.FormatJSON(pols.Policies[n]))
		p.Exists = true
		v.Policies = append(v.Policies, p)
	}
	return v, nil
}

// namedPolicy is the form of the identity's policy name holding doc.
func (m *Module) namedPolicy(identity, name, doc string) *web.Policy {
	return &web.Policy{
		ID:           "policy-" + name,
		Name:         name,
		Named:        true,
		Document:     doc,
		Action:       Path + "/identity/policy",
		DeleteAction: Path + "/identity/policy/delete",
		Fields:       []web.Field{{Name: "identity", Value: identity}},
	}
}

func (m *Module) identity(c gas.Context) error {
	name := c.Query("name")
	v, err := m.loadIdentity(c, name)
	if err != nil {
		return m.render.Fail(c, Key, name, err)
	}
	return m.render.Render(c, web.Page{
		Name: "mail/identity", Title: name, Section: Key, Data: v,
	})
}

// putPolicy creates the identity's policy of the posted name, or replaces
// the document of one it has. A name or document mailbox refuses, such as
// BadRequestException or AlreadyExistsException, is shown next to that
// policy's form with what was typed.
func (m *Module) putPolicy(c gas.Context) error {
	form := c.Request().PostForm
	identity, doc := form.Get("identity"), form.Get("document")
	name, isNew := strings.TrimSpace(form.Get("name")), form.Get("new") == "true"
	var err error
	switch {
	case name == "":
		err = &web.BadInput{Message: "Enter a policy name."}
	case strings.TrimSpace(doc) == "":
		err = &web.BadInput{Message: "Enter the policy document."}
	case isNew:
		_, err = m.ses(c).CreateEmailIdentityPolicy(c, &sesv2.CreateEmailIdentityPolicyInput{
			EmailIdentity: aws.String(identity), PolicyName: aws.String(name),
			Policy: aws.String(doc),
		})
	default:
		_, err = m.ses(c).UpdateEmailIdentityPolicy(c, &sesv2.UpdateEmailIdentityPolicyInput{
			EmailIdentity: aws.String(identity), PolicyName: aws.String(name),
			Policy: aws.String(doc),
		})
	}
	if err != nil {
		return m.refused(c, identity, name, doc, isNew, err)
	}
	verb := "Saved"
	if isNew {
		verb = "Created"
	}
	return web.Done(c, identityLink(identity), verb+" policy "+name+" of "+identity+".")
}

func (m *Module) deletePolicy(c gas.Context) error {
	form := c.Request().PostForm
	identity, name := form.Get("identity"), form.Get("name")
	_, err := m.ses(c).DeleteEmailIdentityPolicy(c, &sesv2.DeleteEmailIdentityPolicyInput{
		EmailIdentity: aws.String(identity), PolicyName: aws.String(name),
	})
	if err != nil {
		return m.refused(c, identity, name, "", false, err)
	}
	return web.Done(c, identityLink(identity), "Deleted policy "+name+" of "+identity+".")
}

// refused shows the identity's page with err next to the form of policy
// name, or of the new policy when isNew, with doc in it, or the stored
// document when doc is "".
func (m *Module) refused(
	c gas.Context, identity, name, doc string, isNew bool, err error,
) error {
	v, lerr := m.loadIdentity(c, identity)
	if lerr != nil {
		return m.render.Fail(c, Key, identity, lerr)
	}
	p := v.New
	if !isNew {
		i := slices.IndexFunc(v.Policies, func(p *web.Policy) bool { return p.Name == name })
		if i < 0 {
			// Gone since the page was read, or unreadable: the answer is
			// shown on a form of its own, with what was sent.
			p = m.namedPolicy(identity, name, doc)
			p.Exists = true
			v.Policies = append(v.Policies, p)
		} else {
			p = v.Policies[i]
		}
	} else {
		p.Name = name
	}
	if doc == "" {
		doc = p.Document
	}
	status := p.Refuse(doc, err)
	return m.render.Render(c, web.Page{
		Name: "mail/identity", Title: identity, Section: Key, Data: v, Status: status,
	})
}
