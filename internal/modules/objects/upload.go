package objects

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// PartSize is the size of each part an upload is sent in, and so the most
// of an upload the console holds in memory at once. It is above S3's 5 MiB
// minimum part size.
const PartSize = 8 << 20

// Uploader is the part of the S3 client an upload calls.
type Uploader interface {
	PutObject(
		context.Context,
		*s3.PutObjectInput,
		...func(*s3.Options),
	) (*s3.PutObjectOutput, error)
	CreateMultipartUpload(
		context.Context, *s3.CreateMultipartUploadInput, ...func(*s3.Options),
	) (*s3.CreateMultipartUploadOutput, error)
	UploadPart(
		context.Context,
		*s3.UploadPartInput,
		...func(*s3.Options),
	) (*s3.UploadPartOutput, error)
	CompleteMultipartUpload(
		context.Context, *s3.CompleteMultipartUploadInput, ...func(*s3.Options),
	) (*s3.CompleteMultipartUploadOutput, error)
	AbortMultipartUpload(
		context.Context, *s3.AbortMultipartUploadInput, ...func(*s3.Options),
	) (*s3.AbortMultipartUploadOutput, error)
}

// Upload streams body to bucket under key with contentType and returns
// the bytes sent. A body that fits in one part is one PutObject; a larger
// one is a multipart upload of PartSize parts, aborted when a part fails.
// Each part is held in memory, so the SDK can sign its hash over plain
// HTTP, which it cannot do for a stream.
func Upload(
	ctx context.Context,
	api Uploader,
	bucket, key, contentType string,
	body io.Reader,
) (int64, error) {
	buf := make([]byte, PartSize)
	n, err := io.ReadFull(body, buf)
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		_, err = api.PutObject(ctx, &s3.PutObjectInput{
			Bucket:        aws.String(bucket),
			Key:           aws.String(key),
			ContentType:   aws.String(contentType),
			ContentLength: aws.Int64(int64(n)),
			Body:          bytes.NewReader(buf[:n]),
		})
		if err != nil {
			return 0, fmt.Errorf("put object: %w", err)
		}
		return int64(n), nil
	}
	if err != nil {
		return 0, fmt.Errorf("read upload: %w", err)
	}

	created, err := api.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket:      aws.String(bucket),
		Key:         aws.String(key),
		ContentType: aws.String(contentType),
	})
	if err != nil {
		return 0, fmt.Errorf("create multipart upload: %w", err)
	}
	total, err := uploadParts(ctx, api, bucket, key, created.UploadId, buf, n, body)
	if err != nil {
		// The upload failed already; the abort only frees its parts, and
		// its own failure is joined to the report.
		_, abortErr := api.AbortMultipartUpload(
			context.WithoutCancel(ctx),
			&s3.AbortMultipartUploadInput{
				Bucket: aws.String(bucket), Key: aws.String(key), UploadId: created.UploadId,
			},
		)
		if abortErr != nil {
			err = errors.Join(err, fmt.Errorf("abort multipart upload: %w", abortErr))
		}
		return 0, err
	}
	return total, nil
}

// uploadParts sends the first part, buf[:n], and the rest of body, and
// completes the upload.
func uploadParts(
	ctx context.Context, api Uploader, bucket, key string, uploadID *string,
	buf []byte, n int, body io.Reader,
) (int64, error) {
	var parts []types.CompletedPart
	var total int64
	for number := int32(1); ; number++ {
		out, err := api.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:        aws.String(bucket),
			Key:           aws.String(key),
			UploadId:      uploadID,
			PartNumber:    aws.Int32(number),
			ContentLength: aws.Int64(int64(n)),
			Body:          bytes.NewReader(buf[:n]),
		})
		if err != nil {
			return 0, fmt.Errorf("upload part %d: %w", number, err)
		}
		parts = append(parts, types.CompletedPart{ETag: out.ETag, PartNumber: aws.Int32(number)})
		total += int64(n)

		n, err = io.ReadFull(body, buf)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
			return 0, fmt.Errorf("read upload: %w", err)
		}
	}
	_, err := api.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket:          aws.String(bucket),
		Key:             aws.String(key),
		UploadId:        uploadID,
		MultipartUpload: &types.CompletedMultipartUpload{Parts: parts},
	})
	if err != nil {
		return 0, fmt.Errorf("complete multipart upload: %w", err)
	}
	return total, nil
}
