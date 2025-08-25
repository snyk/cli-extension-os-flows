package bundlestore

import (
	"context"
	"fmt"
	"os"

	"github.com/google/uuid"
)

type FakeClient struct {
	uploads map[string]string // path -> bundle hash
	err     error
}

var _ Client = (*FakeClient)(nil)

// NewFakeClient creates a new fake bundlestore client.
func NewFakeClient() *FakeClient {
	return &FakeClient{
		uploads: make(map[string]string),
	}
}

// WithError configures the fake to return an error.
func (f *FakeClient) WithError(err error) *FakeClient {
	f.err = err
	return f
}

func (f *FakeClient) uploadPath(_ context.Context, path string) (string, error) {
	if f.err != nil {
		return "", f.err
	}

	if _, err := os.Stat(path); err != nil {
		return "", fmt.Errorf("path does not exist: %s", path)
	}

	bundleHash := uuid.NewString()
	f.uploads[path] = bundleHash

	return bundleHash, nil
}

func (f *FakeClient) UploadSourceCode(ctx context.Context, sourceCodePath string) (string, error) {
	return f.uploadPath(ctx, sourceCodePath)
}

func (f *FakeClient) UploadSBOM(ctx context.Context, sbomPath string) (string, error) {
	return f.uploadPath(ctx, sbomPath)
}

func (f *FakeClient) GetUploadedBundleHash(path string) string {
	return f.uploads[path]
}

func (f *FakeClient) GetUploadCount() int {
	return len(f.uploads)
}
