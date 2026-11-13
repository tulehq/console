package objects

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gasmod/gas"

	"tule.dev/console/internal/web"
)

// policyExample is the example a bucket without a policy shows in its
// empty form.
const policyExample = `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadObjects",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::111122223333:root"},
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::BUCKET/*"
    }
  ]
}`

func bucketLink(bucket string) string {
	return web.Link(Path+"/bucket", "bucket", bucket)
}

// loadPolicy reads the bucket's policy. A bucket without one has an empty
// form, and a policy that cannot be read, such as one the principal may
// not read, has the service's answer in its place.
func loadPolicy(ctx context.Context, api API, bucket string) *web.Policy {
	p := &web.Policy{
		ID:           "bucket-policy",
		Action:       Path + "/bucket/policy",
		DeleteAction: Path + "/bucket/policy/delete",
		Fields:       []web.Field{{Name: "bucket", Value: bucket}},
		Placeholder:  strings.ReplaceAll(policyExample, "BUCKET", bucket),
	}
	doc, err := readPolicy(ctx, api, bucket)
	switch {
	case err != nil:
		p.ReadErr = web.ReadFailure(err)
	case doc != "":
		p.Exists = true
		p.Document = web.FormatJSON(doc)
	}
	p.Fields = append(p.Fields, web.Field{Name: web.LoadedField, Value: web.PolicyVersion(doc)})
	return p
}

// readPolicy returns the bucket's policy as stored, "" for none.
func readPolicy(ctx context.Context, api API, bucket string) (string, error) {
	out, err := api.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: aws.String(bucket)})
	if web.Code(err) == "NoSuchBucketPolicy" {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return aws.ToString(out.Policy), nil
}

// unchanged refuses a change to the bucket's policy unless it is still the
// one the page was read with, so a change made since is not lost.
func unchanged(c gas.Context, api API, bucket string) error {
	stored, err := readPolicy(c, api, bucket)
	if err != nil {
		return err
	}
	return web.Unchanged(c.Request().PostForm.Get(web.LoadedField), stored)
}

// putPolicy attaches the posted policy to the bucket, replacing its own.
// A document object-store refuses, such as MalformedPolicy, is shown next
// to the form with what was typed.
func (m *Module) putPolicy(c gas.Context) error {
	form := c.Request().PostForm
	bucket, doc := form.Get("bucket"), form.Get("document")
	api := m.client(c)
	var err error
	if strings.TrimSpace(doc) == "" {
		err = &web.BadInput{Message: "Enter the policy document."}
	} else if err = unchanged(c, api, bucket); err == nil {
		_, err = api.PutBucketPolicy(c, &s3.PutBucketPolicyInput{
			Bucket: aws.String(bucket), Policy: aws.String(doc),
		})
	}
	if err != nil {
		return m.refused(c, bucket, doc, err)
	}
	return web.Done(c, bucketLink(bucket), "Saved the policy of bucket "+bucket+".")
}

func (m *Module) deletePolicy(c gas.Context) error {
	bucket := c.Request().PostForm.Get("bucket")
	api := m.client(c)
	err := unchanged(c, api, bucket)
	if err == nil {
		_, err = api.DeleteBucketPolicy(c, &s3.DeleteBucketPolicyInput{
			Bucket: aws.String(bucket),
		})
	}
	if err != nil {
		return m.refused(c, bucket, "", err)
	}
	return web.Done(c, bucketLink(bucket), "Deleted the policy of bucket "+bucket+".")
}

// refused shows the bucket's page with err next to its policy's form, and
// doc in it, or the stored document when doc is "".
func (m *Module) refused(c gas.Context, bucket, doc string, err error) error {
	v, lerr := m.load(c, bucket, "", "")
	if lerr != nil {
		return m.render.FailRefused(c, Key, bucket, err, lerr)
	}
	if doc == "" {
		doc = v.Policy.Document
	}
	status := v.Policy.Refuse(doc, err)
	return m.render.Render(c, web.Page{
		Name: "objects/bucket", Title: bucket, Section: Key, Data: v, Status: status,
	})
}
