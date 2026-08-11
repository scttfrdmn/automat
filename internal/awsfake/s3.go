// Copyright 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package awsfake

import (
	"bytes"
	"context"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/scttfrdmn/automat/internal/awsapi"
)

// S3 fakes awsapi.S3MirrorAPI.
//
// An in-memory map keyed by "<bucket>/<key>" stands in for a bucket: what
// this fake exists to exercise is the wiring (evidence.S3Mirror.Upload
// calling PutObject with the right bucket, key, and bytes), not S3's own
// storage or consistency guarantees.
type S3 struct {
	Recorder

	// PutObjectErr, when set, fails every PutObject call — the s3:PutObject
	// denial path evidence.S3Mirror.Upload reports remediation text for.
	PutObjectErr error
	// GetObjectErr, when set, fails every GetObject call.
	GetObjectErr error

	objects map[string][]byte
}

// NewS3 returns an S3 fake with no objects seeded.
func NewS3() *S3 { return &S3{objects: map[string][]byte{}} }

func s3Key(bucket, key string) string { return bucket + "/" + key }

// PutObject implements awsapi.S3MirrorAPI.
func (f *S3) PutObject(_ context.Context, in *s3.PutObjectInput,
	_ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	f.Record("PutObject")
	if f.PutObjectErr != nil {
		return nil, f.PutObjectErr
	}
	var data []byte
	if in.Body != nil {
		var err error
		data, err = io.ReadAll(in.Body)
		if err != nil {
			return nil, err
		}
	}
	if f.objects == nil {
		f.objects = map[string][]byte{}
	}
	f.objects[s3Key(aws.ToString(in.Bucket), aws.ToString(in.Key))] = data
	return &s3.PutObjectOutput{}, nil
}

// GetObject implements awsapi.S3MirrorAPI.
func (f *S3) GetObject(_ context.Context, in *s3.GetObjectInput,
	_ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	f.Record("GetObject")
	if f.GetObjectErr != nil {
		return nil, f.GetObjectErr
	}
	data, ok := f.objects[s3Key(aws.ToString(in.Bucket), aws.ToString(in.Key))]
	if !ok {
		return nil, &types.NoSuchKey{}
	}
	return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(data))}, nil
}

// Object returns what was last PutObject'd at bucket/key, for a test to
// assert against directly rather than round-tripping through GetObject.
func (f *S3) Object(bucket, key string) ([]byte, bool) {
	data, ok := f.objects[s3Key(bucket, key)]
	return data, ok
}

var _ awsapi.S3MirrorAPI = (*S3)(nil)
