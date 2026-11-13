//go:build e2e

package e2e

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sesv2/types"
	"golang.org/x/net/html/atom"

	"tule.dev/console/internal/awsclient"
	"tule.dev/console/internal/consoletest"
	"tule.dev/console/internal/modules/mail"
)

// sendMail sends a message with a text and an HTML part and an
// attachment, and returns its SES MessageId.
func sendMail(t *testing.T, ses *sesv2.Client, to, subject string) string {
	t.Helper()
	out, err := ses.SendEmail(t.Context(), &sesv2.SendEmailInput{
		FromEmailAddress: aws.String("Sender <sender@example.com>"),
		Destination:      &types.Destination{ToAddresses: []string{to}},
		EmailTags: []types.MessageTag{
			{Name: aws.String("kind"), Value: aws.String("welcome")},
		},
		Content: &types.EmailContent{Simple: &types.Message{
			Subject: &types.Content{Data: aws.String(subject)},
			Body: &types.Body{
				Text: &types.Content{Data: aws.String("Hello in text.")},
				Html: &types.Content{
					Data: aws.String(
						`<p>Hello</p><script>alert(1)</script><img src="https://tracker.example/p.gif">`,
					),
				},
			},
			Attachments: []types.Attachment{
				{
					FileName: aws.String(
						"report.csv",
					),
					ContentType: aws.String("text/csv"),
					RawContent:  []byte("a,b\n1,2\n"),
				},
			},
		}},
	})
	requireNoErr(t, err, "send email")
	return aws.ToString(out.MessageId)
}

func TestMailbox(t *testing.T) {
	ses := awsclient.SESv2(endpoint("mailbox"), rootCreds)
	retrieval := mail.NewClient(endpoint("mailbox"), rootCreds)
	to := unique("someone") + "@example.com"
	subject := unique("Welcome ")
	messageID := sendMail(t, ses, to, subject)
	sendMail(t, ses, "other@example.com", unique("Other "))

	b := rootBrowser(t)
	res := b.Get("/mail?" + url.Values{"to": {to}}.Encode())
	consoletest.RequireStatus(t, res, http.StatusOK)
	consoletest.RequireText(t, res, subject, "kind:welcome", "1 attached")
	if strings.Contains(consoletest.Text(res.Doc), "Other ") {
		t.Fatal("the To filter kept another message")
	}

	// Full-text search, as HTMX sends it while typing.
	res = b.HTMX("/mail?" + url.Values{"q": {strings.TrimPrefix(subject, "Welcome ")}}.Encode())
	consoletest.RequireText(t, res, subject)

	res = b.Get("/mail?" + url.Values{"messageId": {messageID}, "tag": {"kind:welcome"}}.Encode())
	link := consoletest.Href(res.Doc, subject)
	if link == "" {
		t.Fatalf("no link to the message: %s", consoletest.Text(res.Doc))
	}
	id := strings.TrimPrefix(link, "/mail/message?id=")

	page := b.Get(link)
	consoletest.RequireStatus(t, page, http.StatusOK)
	consoletest.RequireText(t, page, "Hello in text.", "report.csv", "Message-ID", to)
	consoletest.RequireInert(t, page)
	frame := consoletest.Find(page.Doc, consoletest.Element(atom.Iframe))
	src, _ := consoletest.Attr(frame, "src")
	preview := b.Get(src)
	if !strings.Contains(string(preview.Body), "<script>alert(1)</script>") ||
		!strings.Contains(preview.Header.Get("Content-Security-Policy"), "default-src 'none'") {
		t.Fatalf(
			"preview %q with CSP %q",
			preview.Body,
			preview.Header.Get("Content-Security-Policy"),
		)
	}

	att := b.Get(consoletest.Href(page.Doc, "report.csv"))
	if string(att.Body) != "a,b\n1,2\n" ||
		!strings.HasPrefix(att.Header.Get("Content-Disposition"), "attachment") {
		t.Fatalf("attachment %q, %v", att.Body, att.Header)
	}
	raw := b.Get("/mail/message/raw?id=" + id)
	if !strings.Contains(string(raw.Body), "Subject: "+subject) {
		t.Fatalf("raw %q", raw.Body)
	}

	res = b.PostForm("/mail/message/delete", url.Values{"id": {id}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Deleted the message.")
	if _, err := retrieval.Message(t.Context(), id); err == nil {
		t.Fatal("the deleted message is still stored")
	}
}

func TestRenderingFailuresAndReset(t *testing.T) {
	ses := awsclient.SESv2(endpoint("mailbox"), rootCreds)
	template := unique("Welcome")
	_, err := ses.CreateEmailTemplate(t.Context(), &sesv2.CreateEmailTemplateInput{
		TemplateName: aws.String(template),
		TemplateContent: &types.EmailTemplateContent{
			Subject: aws.String("Hi {{name}}"), Text: aws.String("Hello {{name}}"),
		},
	})
	requireNoErr(t, err, "create template")
	_, err = ses.SendEmail(t.Context(), &sesv2.SendEmailInput{
		FromEmailAddress: aws.String("sender@example.com"),
		Destination:      &types.Destination{ToAddresses: []string{"x@example.com"}},
		Content: &types.EmailContent{Template: &types.Template{
			TemplateName: aws.String(template), TemplateData: aws.String(`{}`),
		}},
	})
	requireNoErr(t, err, "send with the template")

	b := rootBrowser(t)
	res := b.Get("/mail/failures?" + url.Values{"template": {template}}.Encode())
	consoletest.RequireStatus(t, res, http.StatusOK)
	consoletest.RequireText(t, res, template, "Attribute 'name' is not present")

	res = b.PostForm("/mail/reset", nil)
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Deleted every message")
	p, err := mail.NewClient(endpoint("mailbox"), rootCreds).Messages(t.Context(), nil)
	requireNoErr(t, err, "list messages")
	if len(p.Items) != 0 {
		t.Fatalf("%d messages after reset", len(p.Items))
	}
}
