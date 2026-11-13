// Package objects is the object-store section: buckets, browsing a bucket
// by prefix, object details, downloads and uploads streamed through the
// console, deleting objects, and creating and deleting empty buckets.
package objects

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gasmod/gas"

	"tule.dev/console/internal/web"
)

// Key is the section's key, and Path the path its pages live under.
const (
	Key  = "s3"
	Path = "/s3"
)

const (
	moduleName = "tule/modules/objects"
	// MaxUploads is how many uploads one session may run at once; each
	// holds a PartSize buffer.
	MaxUploads = 2
	// pageSize is how many keys and folders a page of a bucket shows.
	pageSize = 200
)

// API is the part of the S3 client the section calls; *s3.Client is one.
type API interface {
	ListBuckets(
		context.Context,
		*s3.ListBucketsInput,
		...func(*s3.Options),
	) (*s3.ListBucketsOutput, error)
	CreateBucket(
		context.Context,
		*s3.CreateBucketInput,
		...func(*s3.Options),
	) (*s3.CreateBucketOutput, error)
	DeleteBucket(
		context.Context,
		*s3.DeleteBucketInput,
		...func(*s3.Options),
	) (*s3.DeleteBucketOutput, error)
	ListObjectsV2(
		context.Context,
		*s3.ListObjectsV2Input,
		...func(*s3.Options),
	) (*s3.ListObjectsV2Output, error)
	HeadObject(
		context.Context,
		*s3.HeadObjectInput,
		...func(*s3.Options),
	) (*s3.HeadObjectOutput, error)
	GetObject(
		context.Context,
		*s3.GetObjectInput,
		...func(*s3.Options),
	) (*s3.GetObjectOutput, error)
	DeleteObjects(
		context.Context,
		*s3.DeleteObjectsInput,
		...func(*s3.Options),
	) (*s3.DeleteObjectsOutput, error)
	Uploader
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
		g.Get("/", m.buckets)
		g.Post("/buckets", m.createBucket)
		g.Post("/buckets/delete", m.deleteBucket)
		g.Get("/bucket", m.browse)
		g.Get("/object", m.object)
		g.Get("/object/download", m.download)
		g.Post("/upload", m.upload)
		g.Post("/objects/delete", m.deleteObjects)
	})
	return nil
}

// Close releases nothing; the module holds no resources of its own.
func (m *Module) Close(context.Context) error { return nil }

func (m *Module) client(c gas.Context) API {
	return m.newClient(web.FromContext(c).Credentials())
}

// Bucket is a bucket in the list.
type Bucket struct {
	Created time.Time
	Name    string
	Link    string
}

type bucketsView struct {
	Buckets []Bucket
}

func (m *Module) buckets(c gas.Context) error {
	out, err := m.client(c).ListBuckets(c, &s3.ListBucketsInput{})
	if err != nil {
		return m.render.Fail(c, Key, "Buckets", err)
	}
	v := bucketsView{}
	for _, b := range out.Buckets {
		name := aws.ToString(b.Name)
		v.Buckets = append(v.Buckets, Bucket{
			Name:    name,
			Created: aws.ToTime(b.CreationDate),
			Link:    web.Link(Path+"/bucket", "bucket", name),
		})
	}
	return m.render.Render(
		c,
		web.Page{Name: "objects/buckets", Title: "Buckets", Section: Key, Data: v},
	)
}

func (m *Module) createBucket(c gas.Context) error {
	name := strings.TrimSpace(c.Request().PostForm.Get("bucket"))
	if name == "" {
		return web.Invalid(c, Path, "Enter a bucket name.")
	}
	_, err := m.client(c).CreateBucket(c, &s3.CreateBucketInput{Bucket: aws.String(name)})
	if err != nil {
		return web.Failed(c, Path, "Bucket "+name+" was not created", err)
	}
	return web.Done(c, web.Link(Path+"/bucket", "bucket", name), "Created bucket "+name+".")
}

func (m *Module) deleteBucket(c gas.Context) error {
	name := c.Request().PostForm.Get("bucket")
	_, err := m.client(c).DeleteBucket(c, &s3.DeleteBucketInput{Bucket: aws.String(name)})
	if err != nil {
		return web.Failed(c, web.Link(Path+"/bucket", "bucket", name),
			"Bucket "+name+" was not deleted", err)
	}
	return web.Done(c, Path, "Deleted bucket "+name+".")
}

// Crumb is one step of the path to a prefix.
type Crumb struct {
	Name string
	Link string
}

// Folder is a common prefix under the prefix being browsed.
type Folder struct {
	Name string
	Link string
}

// Object is an object under the prefix being browsed.
type Object struct {
	Modified time.Time
	Key      string
	Name     string
	ETag     string
	Link     string
	Download string
	Size     int64
}

type browseView struct {
	Bucket    string
	Prefix    string
	NextLink  string
	FirstLink string
	Crumbs    []Crumb
	Folders   []Folder
	Objects   []Object
}

func (m *Module) browse(c gas.Context) error {
	bucket, prefix, token := c.Query("bucket"), c.Query("prefix"), c.Query("token")
	in := &s3.ListObjectsV2Input{
		Bucket:    aws.String(bucket),
		Prefix:    aws.String(prefix),
		Delimiter: aws.String("/"),
		MaxKeys:   aws.Int32(pageSize),
	}
	if token != "" {
		in.ContinuationToken = aws.String(token)
	}
	out, err := m.client(c).ListObjectsV2(c, in)
	if err != nil {
		return m.render.Fail(c, Key, bucket, err)
	}

	v := browseView{Bucket: bucket, Prefix: prefix, Crumbs: crumbs(bucket, prefix)}
	for _, p := range out.CommonPrefixes {
		full := aws.ToString(p.Prefix)
		v.Folders = append(v.Folders, Folder{
			Name: strings.TrimPrefix(full, prefix),
			Link: web.Link(Path+"/bucket", "bucket", bucket, "prefix", full),
		})
	}
	for _, o := range out.Contents {
		key := aws.ToString(o.Key)
		v.Objects = append(v.Objects, Object{
			Key:      key,
			Name:     strings.TrimPrefix(key, prefix),
			Size:     aws.ToInt64(o.Size),
			Modified: aws.ToTime(o.LastModified),
			ETag:     aws.ToString(o.ETag),
			Link:     web.Link(Path+"/object", "bucket", bucket, "key", key),
			Download: web.Link(Path+"/object/download", "bucket", bucket, "key", key),
		})
	}
	if aws.ToBool(out.IsTruncated) && aws.ToString(out.NextContinuationToken) != "" {
		v.NextLink = web.Link(Path+"/bucket", "bucket", bucket, "prefix", prefix,
			"token", aws.ToString(out.NextContinuationToken))
	}
	if token != "" {
		v.FirstLink = web.Link(Path+"/bucket", "bucket", bucket, "prefix", prefix)
	}
	return m.render.Render(
		c,
		web.Page{Name: "objects/bucket", Title: bucket, Section: Key, Data: v},
	)
}

// crumbs returns the steps from the bucket's root to prefix, each a link
// to that prefix.
func crumbs(bucket, prefix string) []Crumb {
	out := []Crumb{{Name: bucket, Link: web.Link(Path+"/bucket", "bucket", bucket)}}
	acc := ""
	for part := range strings.SplitAfterSeq(prefix, "/") {
		if part == "" {
			continue
		}
		acc += part
		out = append(
			out,
			Crumb{Name: part, Link: web.Link(Path+"/bucket", "bucket", bucket, "prefix", acc)},
		)
	}
	return out
}

// Header is a name and a value of an object's metadata.
type Header struct {
	Name  string
	Value string
}

type objectView struct {
	Modified    time.Time
	Bucket      string
	Key         string
	ContentType string
	ETag        string
	Download    string
	Parent      string
	Prefix      string
	Headers     []Header
	Metadata    []Header
	Size        int64
}

func (m *Module) object(c gas.Context) error {
	bucket, key := c.Query("bucket"), c.Query("key")
	out, err := m.client(c).
		HeadObject(c, &s3.HeadObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
	if err != nil {
		return m.render.Fail(c, Key, key, err)
	}
	prefix := ""
	if i := strings.LastIndexByte(key, '/'); i >= 0 {
		prefix = key[:i+1]
	}
	v := objectView{
		Bucket:      bucket,
		Key:         key,
		Prefix:      prefix,
		Size:        aws.ToInt64(out.ContentLength),
		ContentType: aws.ToString(out.ContentType),
		ETag:        aws.ToString(out.ETag),
		Modified:    aws.ToTime(out.LastModified),
		Download:    web.Link(Path+"/object/download", "bucket", bucket, "key", key),
		Parent:      web.Link(Path+"/bucket", "bucket", bucket, "prefix", prefix),
	}
	for _, h := range []Header{
		{"Content-Type", aws.ToString(out.ContentType)},
		{"Content-Length", strconv.FormatInt(aws.ToInt64(out.ContentLength), 10)},
		{"ETag", aws.ToString(out.ETag)},
		{"Last-Modified", web.FormatTime(aws.ToTime(out.LastModified))},
		{"Cache-Control", aws.ToString(out.CacheControl)},
		{"Content-Disposition", aws.ToString(out.ContentDisposition)},
		{"Content-Encoding", aws.ToString(out.ContentEncoding)},
		{"Content-Language", aws.ToString(out.ContentLanguage)},
		{"Expires", aws.ToString(out.ExpiresString)},
		{"Storage class", string(out.StorageClass)},
	} {
		if h.Value != "" {
			v.Headers = append(v.Headers, h)
		}
	}
	for k, val := range out.Metadata {
		v.Metadata = append(v.Metadata, Header{Name: "x-amz-meta-" + k, Value: val})
	}
	sort.Slice(v.Metadata, func(i, j int) bool { return v.Metadata[i].Name < v.Metadata[j].Name })
	return m.render.Render(c, web.Page{Name: "objects/object", Title: key, Section: Key, Data: v})
}

// download streams an object to the browser as an attachment, so no
// object is ever shown on the console's origin, whatever its type.
func (m *Module) download(c gas.Context) error {
	bucket, key := c.Query("bucket"), c.Query("key")
	out, err := m.client(c).
		GetObject(c, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
	if err != nil {
		return m.render.Fail(c, Key, key, err)
	}
	defer func() { _ = out.Body.Close() }()

	h := c.ResponseWriter().Header()
	web.AttachmentHeaders(h, path.Base(key), aws.ToString(out.ContentType))
	if out.ContentLength != nil {
		h.Set("Content-Length", strconv.FormatInt(*out.ContentLength, 10))
	}
	c.ResponseWriter().WriteHeader(http.StatusOK)
	if _, err = io.Copy(c.ResponseWriter(), out.Body); err != nil {
		// The status is sent; all that is left is to cut the response
		// short, which the browser reports as a failed download.
		panic(http.ErrAbortHandler)
	}
	return nil
}

// uploadForm is the text fields of the upload form, which come before its
// file.
type uploadForm struct {
	bucket      string
	prefix      string
	key         string
	contentType string
}

// maxField bounds a text field of the upload form.
const maxField = 4096

func (m *Module) upload(c gas.Context) error {
	mr, err := web.Multipart(c.Request())
	if err != nil {
		return web.Invalid(c, Path, "The upload must be sent as a multipart form.")
	}
	var f uploadForm
	for {
		part, perr := mr.NextPart()
		if errors.Is(perr, io.EOF) {
			return web.Invalid(c, back(f), "Choose a file to upload.")
		}
		if perr != nil {
			return web.Invalid(c, back(f), "The upload could not be read.")
		}
		if part.FormName() != "file" {
			if err = f.set(part.FormName(), part); err != nil {
				return web.Invalid(c, back(f), "The upload form could not be read.")
			}
			continue
		}
		return m.store(c, f, part.FileName(), part.Header.Get("Content-Type"), part)
	}
}

func (f *uploadForm) set(name string, r io.Reader) error {
	b, err := io.ReadAll(io.LimitReader(r, maxField+1))
	if err != nil {
		return fmt.Errorf("read field %s: %w", name, err)
	}
	if len(b) > maxField {
		return fmt.Errorf("field %s is too long", name)
	}
	s := string(b)
	switch name {
	case "bucket":
		f.bucket = s
	case "prefix":
		f.prefix = s
	case "key":
		f.key = strings.TrimSpace(s)
	case "contentType":
		f.contentType = strings.TrimSpace(s)
	}
	return nil
}

func back(f uploadForm) string {
	if f.bucket == "" {
		return Path
	}
	return web.Link(Path+"/bucket", "bucket", f.bucket, "prefix", f.prefix)
}

// store streams the file part to the bucket under the form's key, or the
// prefix and the file's name.
func (m *Module) store(
	c gas.Context,
	f uploadForm,
	fileName, partType string,
	body io.Reader,
) error {
	if f.bucket == "" {
		return web.Invalid(c, Path, "The upload names no bucket.")
	}
	key := f.objectKey(fileName)
	if key == "" {
		return web.Invalid(c, back(f), "Choose a file to upload.")
	}
	ct := f.mediaType(partType)
	if _, _, err := mime.ParseMediaType(ct); err != nil {
		return web.Invalid(c, back(f), "The content type is not a media type.")
	}
	sess := web.FromContext(c)
	if !sess.StartUpload(MaxUploads) {
		return web.Invalid(c, back(f), fmt.Sprintf(
			"This session is running %d uploads already. Wait for one to finish.", MaxUploads))
	}
	defer sess.DoneUpload()
	n, err := Upload(c, m.client(c), f.bucket, key, ct, body)
	if err != nil {
		return web.Failed(c, back(f), "Upload of "+key+" failed", err)
	}
	return web.Done(c, back(f), fmt.Sprintf("Uploaded %s (%s).", key, web.FormatBytes(n)))
}

// objectKey is the form's key, or the prefix and the base of the file's
// name, or "" when the form names neither.
func (f uploadForm) objectKey(fileName string) string {
	if f.key != "" {
		return f.key
	}
	base := path.Base(strings.ReplaceAll(fileName, "\\", "/"))
	if fileName == "" || base == "." || base == "/" {
		return ""
	}
	return f.prefix + base
}

// mediaType is the form's content type, or the file part's, or
// application/octet-stream.
func (f uploadForm) mediaType(partType string) string {
	switch {
	case f.contentType != "":
		return f.contentType
	case partType != "":
		return partType
	default:
		return "application/octet-stream"
	}
}

func (m *Module) deleteObjects(c gas.Context) error {
	form := c.Request().PostForm
	bucket, prefix := form.Get("bucket"), form.Get("prefix")
	target := web.Link(Path+"/bucket", "bucket", bucket, "prefix", prefix)
	keys := form["key"]
	if len(keys) == 0 {
		return web.Invalid(c, target, "Select the objects to delete.")
	}
	ids := make([]types.ObjectIdentifier, len(keys))
	for i, k := range keys {
		ids[i] = types.ObjectIdentifier{Key: aws.String(k)}
	}
	out, err := m.client(c).DeleteObjects(c, &s3.DeleteObjectsInput{
		Bucket: aws.String(bucket),
		Delete: &types.Delete{Objects: ids, Quiet: aws.Bool(true)},
	})
	if err != nil {
		return web.Failed(c, target, "The objects were not deleted", err)
	}
	if len(out.Errors) > 0 {
		e := out.Errors[0]
		return web.Invalid(c, target, fmt.Sprintf("%d of %d objects were not deleted: %s: %s",
			len(out.Errors), len(keys), aws.ToString(e.Key), aws.ToString(e.Message)))
	}
	if len(keys) == 1 {
		return web.Done(c, target, "Deleted "+keys[0]+".")
	}
	return web.Done(c, target, fmt.Sprintf("Deleted %d objects.", len(keys)))
}
