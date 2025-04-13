// Package minio provides an abstraction layer for interacting with a MinIO storage server.
package minio

import (
	"context"
	"io"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// minIOStorage represents a storage client for interacting with MinIO.
type minIOStorage struct {
	client *minio.Client
	bucket string
}

// New initializes a new MinIO storage bucket with the given credentials.
func New(endpoint, accessKeyID, secretAccessKey, bucket string) (*minIOStorage, error) {
	client, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKeyID, secretAccessKey, ""),
		Secure: false,
	})
	if err != nil {
		return nil, err
	}

	return &minIOStorage{
		client: client,
		bucket: bucket,
	}, nil
}

// SaveFileInChunks uploads a file to MinIO in chunks.
func (m *minIOStorage) SaveFileInChunks(ctx context.Context, objectName string, reader io.Reader) error {
	_, err := m.client.PutObject(ctx, m.bucket, objectName, reader, -1, minio.PutObjectOptions{})
	if err != nil {
		return err
	}

	return nil
}

// ReadFileInChunks retrieves a file from MinIO as a stream.
func (m *minIOStorage) ReadFileInChunks(ctx context.Context, objectName string) (io.ReadCloser, error) {
	object, err := m.client.GetObject(ctx, m.bucket, objectName, minio.GetObjectOptions{})
	if err != nil {
		return nil, err
	}
	return object, nil
}

// DeleteFile removes a file from MinIO storage.
func (m *minIOStorage) DeleteFile(ctx context.Context, objectName string) error {
	err := m.client.RemoveObject(ctx, m.bucket, objectName, minio.RemoveObjectOptions{})
	if err != nil {
		return err
	}

	return nil
}
