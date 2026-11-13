//go:build e2e

package e2e

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"

	"tule.dev/console/internal/awsclient"
	"tule.dev/console/internal/consoletest"
	"tule.dev/console/internal/modules/objects"
)

func s3Client() *s3.Client {
	return awsclient.S3(endpoint("object-store"), rootCreds)
}

func requireCode(t *testing.T, err error, code, what string) {
	t.Helper()
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) || apiErr.ErrorCode() != code {
		t.Fatalf("%s: err %v, want %s", what, err, code)
	}
}

func TestObjectStore(t *testing.T) {
	b := rootBrowser(t)
	bucket := unique("photos-")
	sdk := s3Client()

	res := b.Get("/s3")
	consoletest.RequireStatus(t, res, http.StatusOK)
	res = b.PostForm("/s3/buckets", url.Values{"bucket": {bucket}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Created bucket "+bucket)
	_, err := sdk.HeadBucket(t.Context(), &s3.HeadBucketInput{Bucket: aws.String(bucket)})
	requireNoErr(t, err, "the bucket the console created")

	// Upload into a folder, with a content type.
	b.Get(web(bucket, ""))
	res = b.PostMultipart(
		"/s3/upload",
		consoletest.Field{Name: "bucket", Value: bucket},
		consoletest.Field{Name: "prefix", Value: "2026/"},
		consoletest.Field{
			Name:        "file",
			FileName:    "note.txt",
			ContentType: "text/plain",
			Value:       "hello object",
		},
	)
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Uploaded 2026/note.txt")
	got, err := sdk.GetObject(
		t.Context(),
		&s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String("2026/note.txt")},
	)
	requireNoErr(t, err, "get the uploaded object")
	body, _ := io.ReadAll(got.Body)
	_ = got.Body.Close()
	if string(body) != "hello object" || aws.ToString(got.ContentType) != "text/plain" {
		t.Fatalf("stored %q as %q", body, aws.ToString(got.ContentType))
	}

	browseObject(t, b, bucket)

	// A bucket with an object is not deleted.
	res = b.PostForm("/s3/buckets/delete", url.Values{"bucket": {bucket}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "error", "not deleted")

	res = b.PostForm(
		"/s3/objects/delete",
		url.Values{"bucket": {bucket}, "prefix": {"2026/"}, "key": {"2026/note.txt"}},
	)
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Deleted 2026/note.txt.")
	_, err = sdk.HeadObject(
		t.Context(),
		&s3.HeadObjectInput{Bucket: aws.String(bucket), Key: aws.String("2026/note.txt")},
	)
	requireCode(t, err, "NotFound", "the deleted object")

	res = b.PostForm("/s3/buckets/delete", url.Values{"bucket": {bucket}})
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Deleted bucket "+bucket)
	_, err = sdk.HeadBucket(t.Context(), &s3.HeadBucketInput{Bucket: aws.String(bucket)})
	requireCode(t, err, "NotFound", "the deleted bucket")
}

func web(bucket, prefix string) string {
	q := url.Values{"bucket": {bucket}}
	if prefix != "" {
		q.Set("prefix", prefix)
	}
	return "/s3/bucket?" + q.Encode()
}

// TestLargeUpload streams a file larger than one part through the console,
// which object-store takes as a multipart upload.
func TestLargeUpload(t *testing.T) {
	bucket := unique("big-")
	sdk := s3Client()
	_, err := sdk.CreateBucket(t.Context(), &s3.CreateBucketInput{Bucket: aws.String(bucket)})
	requireNoErr(t, err, "create bucket")

	data := bytes.Repeat([]byte("0123456789abcdef"), (objects.PartSize+3<<20)/16)
	b := rootBrowser(t)
	b.Get(web(bucket, ""))
	res := b.PostMultipart("/s3/upload",
		consoletest.Field{Name: "bucket", Value: bucket},
		consoletest.Field{Name: "file", FileName: "blob.bin", Value: string(data)},
	)
	consoletest.RequireFlash(t, b.Get(res.Location()), "ok", "Uploaded blob.bin")

	got, err := sdk.GetObject(
		t.Context(),
		&s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String("blob.bin")},
	)
	requireNoErr(t, err, "get the large object")
	body, _ := io.ReadAll(got.Body)
	_ = got.Body.Close()
	if !bytes.Equal(body, data) {
		t.Fatalf("stored %d bytes, want %d", len(body), len(data))
	}
	res = b.Get("/s3/object/download?bucket=" + bucket + "&key=blob.bin")
	if !bytes.Equal(res.Body, data) {
		t.Fatalf("downloaded %d bytes, want %d", len(res.Body), len(data))
	}
}

// browseObject browses to the uploaded object and downloads it through
// the console.
func browseObject(t *testing.T, b *consoletest.Browser, bucket string) {
	t.Helper()
	// Browse: the root shows the folder, the folder the object.
	res := b.Get(web(bucket, ""))
	consoletest.RequireText(t, res, "2026/")
	res = b.Get(web(bucket, "2026/"))
	consoletest.RequireText(t, res, "note.txt", "12 B")

	res = b.Get("/s3/object?bucket=" + bucket + "&key=2026%2Fnote.txt")
	consoletest.RequireStatus(t, res, http.StatusOK)
	consoletest.RequireText(t, res, "text/plain", "12 bytes")

	res = b.Get("/s3/object/download?bucket=" + bucket + "&key=2026%2Fnote.txt")
	if res.Status != http.StatusOK || string(res.Body) != "hello object" {
		t.Fatalf("download: %d %q", res.Status, res.Body)
	}
}
