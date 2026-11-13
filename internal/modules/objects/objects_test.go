package objects_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"

	"tule.dev/console/internal/app"
	"tule.dev/console/internal/consoletest"
	"tule.dev/console/internal/modules/objects"
)

type object struct {
	modified    time.Time
	meta        map[string]string
	contentType string
	body        []byte
}

// fakeS3 is an S3 of buckets in memory, enough of one for the section.
type fakeS3 struct {
	buckets map[string]map[string]object
	uploads map[string][][]byte
	held    chan struct{}
	release chan struct{}
	creds   []aws.Credentials
	puts    int
	mu      sync.Mutex
}

func newFake() *fakeS3 {
	return &fakeS3{buckets: map[string]map[string]object{}, uploads: map[string][][]byte{}}
}

func noBucket(name string) error {
	return &smithy.GenericAPIError{
		Code:    "NoSuchBucket",
		Message: "The bucket " + name + " does not exist.",
	}
}

func (f *fakeS3) ListBuckets(
	context.Context,
	*s3.ListBucketsInput,
	...func(*s3.Options),
) (*s3.ListBucketsOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	names := make([]string, 0, len(f.buckets))
	for n := range f.buckets {
		names = append(names, n)
	}
	sort.Strings(names)
	out := &s3.ListBucketsOutput{}
	for _, n := range names {
		out.Buckets = append(
			out.Buckets,
			types.Bucket{Name: aws.String(n), CreationDate: aws.Time(time.Unix(0, 0))},
		)
	}
	return out, nil
}

func (f *fakeS3) CreateBucket(
	_ context.Context,
	in *s3.CreateBucketInput,
	_ ...func(*s3.Options),
) (*s3.CreateBucketOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.buckets[*in.Bucket] = map[string]object{}
	return &s3.CreateBucketOutput{}, nil
}

func (f *fakeS3) DeleteBucket(
	_ context.Context,
	in *s3.DeleteBucketInput,
	_ ...func(*s3.Options),
) (*s3.DeleteBucketOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.buckets[*in.Bucket]
	if !ok {
		return nil, noBucket(*in.Bucket)
	}
	if len(b) > 0 {
		return nil, &smithy.GenericAPIError{
			Code:    "BucketNotEmpty",
			Message: "The bucket you tried to delete is not empty",
		}
	}
	delete(f.buckets, *in.Bucket)
	return &s3.DeleteBucketOutput{}, nil
}

func (f *fakeS3) ListObjectsV2(
	_ context.Context,
	in *s3.ListObjectsV2Input,
	_ ...func(*s3.Options),
) (*s3.ListObjectsV2Output, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.buckets[*in.Bucket]
	if !ok {
		return nil, noBucket(*in.Bucket)
	}
	prefix := aws.ToString(in.Prefix)
	keys := make([]string, 0, len(b))
	for k := range b {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := &s3.ListObjectsV2Output{}
	seen := map[string]bool{}
	start := aws.ToString(in.ContinuationToken)
	n := 0
	for _, k := range keys {
		if !strings.HasPrefix(k, prefix) || k <= start {
			continue
		}
		if n == int(aws.ToInt32(in.MaxKeys)) {
			out.IsTruncated = aws.Bool(true)
			out.NextContinuationToken = aws.String(start)
			break
		}
		rest := strings.TrimPrefix(k, prefix)
		if i := strings.Index(rest, "/"); i >= 0 {
			p := prefix + rest[:i+1]
			if !seen[p] {
				seen[p] = true
				out.CommonPrefixes = append(
					out.CommonPrefixes,
					types.CommonPrefix{Prefix: aws.String(p)},
				)
			}
		} else {
			o := b[k]
			out.Contents = append(out.Contents, types.Object{
				Key: aws.String(k), Size: aws.Int64(int64(len(o.body))),
				LastModified: aws.Time(o.modified), ETag: aws.String(`"etag"`),
			})
		}
		start = k
		n++
	}
	return out, nil
}

func (f *fakeS3) get(bucket, key string) (object, error) {
	b, ok := f.buckets[bucket]
	if !ok {
		return object{}, noBucket(bucket)
	}
	o, ok := b[key]
	if !ok {
		return object{}, &smithy.GenericAPIError{
			Code:    "NoSuchKey",
			Message: "The specified key does not exist.",
		}
	}
	return o, nil
}

func (f *fakeS3) HeadObject(
	_ context.Context,
	in *s3.HeadObjectInput,
	_ ...func(*s3.Options),
) (*s3.HeadObjectOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	o, err := f.get(*in.Bucket, *in.Key)
	if err != nil {
		return nil, err
	}
	return &s3.HeadObjectOutput{
		ContentLength: aws.Int64(int64(len(o.body))), ContentType: aws.String(o.contentType),
		ETag: aws.String(`"etag"`), LastModified: aws.Time(o.modified), Metadata: o.meta,
	}, nil
}

func (f *fakeS3) GetObject(
	_ context.Context,
	in *s3.GetObjectInput,
	_ ...func(*s3.Options),
) (*s3.GetObjectOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	o, err := f.get(*in.Bucket, *in.Key)
	if err != nil {
		return nil, err
	}
	return &s3.GetObjectOutput{
		Body: io.NopCloser(bytes.NewReader(o.body)), ContentLength: aws.Int64(int64(len(o.body))),
		ContentType: aws.String(o.contentType),
	}, nil
}

func (f *fakeS3) DeleteObjects(
	_ context.Context,
	in *s3.DeleteObjectsInput,
	_ ...func(*s3.Options),
) (*s3.DeleteObjectsOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.buckets[*in.Bucket]
	if !ok {
		return nil, noBucket(*in.Bucket)
	}
	for _, id := range in.Delete.Objects {
		delete(b, *id.Key)
	}
	return &s3.DeleteObjectsOutput{}, nil
}

func (f *fakeS3) PutObject(
	_ context.Context,
	in *s3.PutObjectInput,
	_ ...func(*s3.Options),
) (*s3.PutObjectOutput, error) {
	f.mu.Lock()
	held, release := f.held, f.release
	f.mu.Unlock()
	if held != nil {
		held <- struct{}{}
		<-release
	}
	body, err := io.ReadAll(in.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.buckets[*in.Bucket]
	if !ok {
		return nil, noBucket(*in.Bucket)
	}
	f.puts++
	b[*in.Key] = object{body: body, contentType: aws.ToString(in.ContentType), modified: time.Now()}
	return &s3.PutObjectOutput{}, nil
}

func (f *fakeS3) CreateMultipartUpload(
	_ context.Context, in *s3.CreateMultipartUploadInput, _ ...func(*s3.Options),
) (*s3.CreateMultipartUploadOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := "upload-" + *in.Key
	f.uploads[id] = nil
	return &s3.CreateMultipartUploadOutput{UploadId: aws.String(id)}, nil
}

func (f *fakeS3) UploadPart(
	_ context.Context,
	in *s3.UploadPartInput,
	_ ...func(*s3.Options),
) (*s3.UploadPartOutput, error) {
	body, err := io.ReadAll(in.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.uploads[*in.UploadId] = append(f.uploads[*in.UploadId], body)
	return &s3.UploadPartOutput{ETag: aws.String(`"part"`)}, nil
}

func (f *fakeS3) CompleteMultipartUpload(
	_ context.Context, in *s3.CompleteMultipartUploadInput, _ ...func(*s3.Options),
) (*s3.CompleteMultipartUploadOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(in.MultipartUpload.Parts) != len(f.uploads[*in.UploadId]) {
		return nil, errors.New("part count mismatch")
	}
	f.buckets[*in.Bucket][*in.Key] = object{
		body:     bytes.Join(f.uploads[*in.UploadId], nil),
		modified: time.Now(),
	}
	delete(f.uploads, *in.UploadId)
	return &s3.CompleteMultipartUploadOutput{}, nil
}

func (f *fakeS3) AbortMultipartUpload(
	_ context.Context, in *s3.AbortMultipartUploadInput, _ ...func(*s3.Options),
) (*s3.AbortMultipartUploadOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.uploads, *in.UploadId)
	return &s3.AbortMultipartUploadOutput{}, nil
}

func start(t *testing.T, f *fakeS3) *consoletest.Browser {
	t.Helper()
	s := consoletest.Start(t, app.Overrides{ObjectStore: func(c aws.Credentials) objects.API {
		f.mu.Lock()
		f.creds = append(f.creds, c)
		f.mu.Unlock()
		return f
	}}, nil, "s3")
	b := s.Browser(t)
	b.SignIn(consoletest.KeyID, consoletest.Secret)
	return b
}

func TestBucketsAndBrowse(t *testing.T) {
	f := newFake()
	f.buckets["photos"] = map[string]object{
		"a.txt":         {body: []byte("hello"), contentType: "text/plain"},
		"2026/jan.jpg":  {body: []byte("jpg")},
		"2026/feb/x.md": {body: []byte("x")},
	}
	b := start(t, f)

	res := b.Get("/s3")
	consoletest.RequireStatus(t, res, http.StatusOK)
	if consoletest.Find(res.Doc, consoletest.LinkTo("/s3/bucket?bucket=photos")) == nil {
		t.Fatal("no link to the bucket")
	}
	if f.creds[0].AccessKeyID != consoletest.KeyID ||
		f.creds[0].SecretAccessKey != consoletest.Secret {
		t.Fatal("the client was not built from the session's key")
	}

	res = b.Get("/s3/bucket?bucket=photos")
	consoletest.RequireStatus(t, res, http.StatusOK)
	consoletest.RequireText(t, res, "a.txt", "2026/", "5 B")
	if consoletest.Find(
		res.Doc,
		consoletest.LinkTo("/s3/bucket?bucket=photos&prefix=2026%2F"),
	) == nil {
		t.Fatal("no link into the folder")
	}

	res = b.Get("/s3/bucket?bucket=photos&prefix=2026%2F")
	consoletest.RequireText(t, res, "jan.jpg", "feb/")

	res = b.Get("/s3/object?bucket=photos&key=a.txt")
	consoletest.RequireStatus(t, res, http.StatusOK)
	consoletest.RequireText(t, res, "text/plain", `"etag"`, "5 bytes")
}

func TestBrowsePages(t *testing.T) {
	f := newFake()
	keys := map[string]object{}
	for i := range 450 {
		keys[fmt.Sprintf("k%04d", i)] = object{}
	}
	f.buckets["big"] = keys
	b := start(t, f)
	res := b.Get("/s3/bucket?bucket=big")
	href := consoletest.Href(res.Doc, "Next page")
	if href == "" {
		t.Fatal("no next page link on a bucket of 450 keys")
	}
	res = b.Get(href)
	consoletest.RequireStatus(t, res, http.StatusOK)
	consoletest.RequireText(t, res, "First page")
}

func TestMissingBucketIsAnErrorPage(t *testing.T) {
	b := start(t, newFake())
	res := b.Get("/s3/bucket?bucket=nope")
	consoletest.RequireStatus(t, res, http.StatusBadGateway)
	consoletest.RequireText(t, res, "NoSuchBucket", "does not exist")
}

func TestCreateAndDeleteBucket(t *testing.T) {
	f := newFake()
	b := start(t, f)

	res := b.PostForm("/s3/buckets", url.Values{"bucket": {"new"}})
	consoletest.RequireStatus(t, res, http.StatusSeeOther)
	if _, ok := f.buckets["new"]; !ok {
		t.Fatal("the bucket was not created")
	}
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Created bucket new.")

	f.buckets["new"]["k"] = object{}
	res = b.PostForm("/s3/buckets/delete", url.Values{"bucket": {"new"}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "error", "not empty")

	delete(f.buckets["new"], "k")
	res = b.PostForm("/s3/buckets/delete", url.Values{"bucket": {"new"}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Deleted bucket new.")
	if _, ok := f.buckets["new"]; ok {
		t.Fatal("the bucket was not deleted")
	}
}

func TestUploadDownloadDelete(t *testing.T) {
	f := newFake()
	f.buckets["docs"] = map[string]object{}
	b := start(t, f)
	b.Get("/s3/bucket?bucket=docs")

	res := b.PostMultipart(
		"/s3/upload",
		consoletest.Field{Name: "bucket", Value: "docs"},
		consoletest.Field{Name: "prefix", Value: "in/"},
		consoletest.Field{
			Name:        "file",
			FileName:    "note.html",
			ContentType: "text/html",
			Value:       "<script>alert(1)</script>",
		},
	)
	consoletest.RequireStatus(t, res, http.StatusSeeOther)
	o, ok := f.buckets["docs"]["in/note.html"]
	if !ok || string(o.body) != "<script>alert(1)</script>" || o.contentType != "text/html" {
		t.Fatalf("stored %+v", f.buckets["docs"])
	}
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Uploaded in/note.html")

	res = b.Get("/s3/object/download?bucket=docs&key=in%2Fnote.html")
	consoletest.RequireStatus(t, res, http.StatusOK)
	if string(res.Body) != "<script>alert(1)</script>" {
		t.Fatalf("downloaded %q", res.Body)
	}
	h := res.Header
	if !strings.HasPrefix(h.Get("Content-Disposition"), "attachment") ||
		!strings.Contains(h.Get("Content-Security-Policy"), "sandbox") ||
		h.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("download headers %v: an HTML object must not render on the console's origin", h)
	}

	res = b.PostForm(
		"/s3/objects/delete",
		url.Values{"bucket": {"docs"}, "prefix": {"in/"}, "key": {"in/note.html"}},
	)
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Deleted in/note.html.")
	if len(f.buckets["docs"]) != 0 {
		t.Fatal("the object was not deleted")
	}
}

func TestUploadKeyAndType(t *testing.T) {
	f := newFake()
	f.buckets["docs"] = map[string]object{}
	b := start(t, f)
	b.Get("/s3/bucket?bucket=docs")
	b.PostMultipart("/s3/upload",
		consoletest.Field{Name: "bucket", Value: "docs"},
		consoletest.Field{Name: "key", Value: "custom/name.bin"},
		consoletest.Field{Name: "contentType", Value: "application/x-thing"},
		consoletest.Field{Name: "file", FileName: "ignored.txt", Value: "data"},
	)
	if o := f.buckets["docs"]["custom/name.bin"]; o.contentType != "application/x-thing" {
		t.Fatalf("stored %+v", f.buckets["docs"])
	}
}

func TestUploadNeedsTheTokenFirst(t *testing.T) {
	f := newFake()
	f.buckets["docs"] = map[string]object{}
	b := start(t, f)
	b.Get("/s3/bucket?bucket=docs")
	token := b.CSRF
	b.CSRF = "wrong"
	res := b.PostMultipart("/s3/upload",
		consoletest.Field{Name: "bucket", Value: "docs"},
		consoletest.Field{Name: "_csrf", Value: token},
		consoletest.Field{Name: "file", FileName: "a.txt", Value: "x"},
	)
	consoletest.RequireStatus(t, res, http.StatusForbidden)
	if len(f.buckets["docs"]) != 0 {
		t.Fatal("an upload without its token first was stored")
	}
}

func TestLargeUploadIsMultipart(t *testing.T) {
	f := newFake()
	f.buckets["big"] = map[string]object{}
	body := bytes.Repeat([]byte("0123456789abcdef"), (objects.PartSize*2+1000)/16)
	n, err := objects.Upload(
		t.Context(),
		f,
		"big",
		"blob",
		"application/octet-stream",
		bytes.NewReader(body),
	)
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	if n != int64(len(body)) || !bytes.Equal(f.buckets["big"]["blob"].body, body) || f.puts != 0 {
		t.Fatalf("sent %d of %d bytes, %d puts", n, len(body), f.puts)
	}

	n, err = objects.Upload(t.Context(), f, "big", "small", "text/plain", strings.NewReader("hi"))
	if err != nil || n != 2 || f.puts != 1 {
		t.Fatalf("small upload: n=%d err=%v puts=%d", n, err, f.puts)
	}
}

func TestHostileNamesRenderInert(t *testing.T) {
	f := newFake()
	bucket := map[string]object{}
	for _, h := range consoletest.Hostile {
		bucket[h] = object{body: []byte("x"), contentType: h, meta: map[string]string{h: h}}
		bucket[h+"/"+h] = object{}
	}
	f.buckets[consoletest.HostileName] = bucket
	b := start(t, f)

	for _, path := range []string{
		"/s3",
		"/s3/bucket?bucket=" + url.QueryEscape(consoletest.HostileName),
		"/s3/object?bucket=" + url.QueryEscape(consoletest.HostileName) + "&key=" + url.QueryEscape(consoletest.Hostile[0]),
		"/s3/object?bucket=" + url.QueryEscape(consoletest.HostileName) + "&key=" + url.QueryEscape(consoletest.Hostile[1]),
	} {
		res := b.Get(path)
		consoletest.RequireStatus(t, res, http.StatusOK)
		consoletest.RequireInert(t, res)
	}
	res := b.Get("/s3/bucket?bucket=" + url.QueryEscape(consoletest.HostileName))
	consoletest.RequireText(t, res, consoletest.Hostile[0], consoletest.Hostile[1])
}

func TestUploadsPerSessionAreBounded(t *testing.T) {
	f := newFake()
	f.buckets["docs"] = map[string]object{}
	f.held, f.release = make(chan struct{}), make(chan struct{})
	b := start(t, f)
	b.Get("/s3/bucket?bucket=docs")

	upload := func(key string) *http.Request {
		return b.MultipartRequest("/s3/upload",
			consoletest.Field{Name: "bucket", Value: "docs"},
			consoletest.Field{Name: "key", Value: key},
			consoletest.Field{Name: "file", FileName: key, Value: "data"},
		)
	}
	done := make(chan error, objects.MaxUploads)
	for i := range objects.MaxUploads {
		req := upload(fmt.Sprintf("held-%d", i))
		go func() {
			status, err := b.Send(req)
			if err == nil && status != http.StatusSeeOther {
				err = fmt.Errorf("status %d", status)
			}
			done <- err
		}()
		select {
		case <-f.held:
		case err := <-done:
			t.Fatalf("upload %d ended before it reached the store: %v", i, err)
		case <-time.After(10 * time.Second):
			t.Fatalf("upload %d did not reach the store", i)
		}
	}

	// Both slots are taken: a third upload of the session is refused.
	res := b.Do(upload("third"))
	consoletest.RequireStatus(t, res, http.StatusSeeOther)
	consoletest.RequireFlash(t, b.Get(res.Location()), "error", "running 2 uploads already")
	close(f.release)
	for range objects.MaxUploads {
		if err := <-done; err != nil {
			t.Fatalf("held upload: %v", err)
		}
	}
	if _, ok := f.buckets["docs"]["third"]; ok {
		t.Fatal("the upload past the bound was stored")
	}

	// With the slots free again, an upload goes through.
	f.mu.Lock()
	f.held = nil
	f.mu.Unlock()
	res = b.Do(upload("after"))
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Uploaded after")
}
