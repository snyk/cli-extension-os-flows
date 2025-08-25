package fileupload

import (
	"context"
	"fmt"
	"os"

	"github.com/google/uuid"

	"github.com/snyk/cli-extension-os-flows/internal/fileupload/uploadrevision"
)

type FakeClient struct {
	revisions map[RevisionID][]string
	err       error
}

var _ Client = (*FakeClient)(nil)

// NewFakeClient creates a new fake client.
func NewFakeClient() *FakeClient {
	return &FakeClient{
		revisions: make(map[RevisionID][]string),
	}
}

// WithError configures the fake to return an error.
func (f *FakeClient) WithError(err error) *FakeClient {
	f.err = err
	return f
}

func (f *FakeClient) CreateRevisionFromDir(ctx context.Context, dirPath string, opts UploadOptions) (RevisionID, error) {
	if f.err != nil {
		return uuid.Nil, f.err
	}

	info, err := os.Stat(dirPath)
	if err != nil {
		return uuid.Nil, uploadrevision.NewFileAccessError(dirPath, err)
	}

	if !info.IsDir() {
		return uuid.Nil, fmt.Errorf("the provided path is not a directory: %s", dirPath)
	}

	return f.CreateRevisionFromPaths(ctx, []string{dirPath}, opts)
}

func (f *FakeClient) CreateRevisionFromFile(ctx context.Context, filePath string, opts UploadOptions) (RevisionID, error) {
	if f.err != nil {
		return uuid.Nil, f.err
	}

	info, err := os.Stat(filePath)
	if err != nil {
		return uuid.Nil, uploadrevision.NewFileAccessError(filePath, err)
	}

	if !info.Mode().IsRegular() {
		return uuid.Nil, fmt.Errorf("the provided path is not a regular file: %s", filePath)
	}

	return f.CreateRevisionFromPaths(ctx, []string{filePath}, opts)
}

func (f *FakeClient) CreateRevisionFromPaths(ctx context.Context, paths []string, opts UploadOptions) (RevisionID, error) {
	if f.err != nil {
		return uuid.Nil, f.err
	}

	revID := uuid.New()
	f.revisions[revID] = append([]string(nil), paths...)

	return revID, nil
}

func (f *FakeClient) GetRevisionPaths(revID RevisionID) []string {
	return f.revisions[revID]
}
