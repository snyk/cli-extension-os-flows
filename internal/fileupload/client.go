package fileupload

import (
	"context"
	"os"
	"path/filepath"
	"runtime"

	"github.com/google/uuid"

	listsources "github.com/snyk/cli-extension-os-flows/internal/files"
	"github.com/snyk/cli-extension-os-flows/internal/fileupload/lowlevel"
)

// Config contains configuration for the file upload client.
type Config struct {
	BaseURL string
	OrgID   uuid.UUID
}

// Client provides high-level file upload functionality.
type Client struct {
	orgID    uuid.UUID
	lowlevel lowlevel.SealableClient
}

// Option allows customizing the Client during construction.
type Option func(*Client)

// WithLowLevelClient allows injecting a custom low-level client (primarily for testing).
func WithLowLevelClient(client lowlevel.SealableClient) Option {
	return func(c *Client) {
		c.lowlevel = client
	}
}

// NewClient creates a new high-level file upload client.
// For production use, consumers only need to provide Config.
// For testing, use WithLowLevelClient option to inject a mock.
func NewClient(cfg Config, opts ...Option) *Client {
	client := &Client{
		orgID: cfg.OrgID,
	}

	// Apply options first (allows overriding the low-level client)
	for _, opt := range opts {
		opt(client)
	}

	// Create default low-level client if none was provided
	if client.lowlevel == nil {
		client.lowlevel = lowlevel.NewClient(lowlevel.Config{
			BaseURL: cfg.BaseURL,
		})
	}

	return client
}

func chunkChan[T any](chn <-chan T, size int) <-chan []T {
	out := make(chan []T)
	chunk := make([]T, 0, size)

	go func() {
		defer close(out)

		for el := range chn {
			chunk = append(chunk, el)
			if len(chunk) == size {
				out <- chunk
				chunk = make([]T, 0, size)
			}
		}

		if len(chunk) > 0 {
			out <- chunk
		}
	}()

	return out
}

// UploadDir uploads a directory and all its contents, returning a revision ID.
func (c *Client) UploadDir(ctx context.Context, dir *os.File) (RevisionID, error) {
	revision, err := c.lowlevel.CreateRevision(ctx, c.orgID)
	if err != nil {
		return uuid.Nil, err
	}

	sources, err := listsources.ForPath(dir.Name(), nil, runtime.NumCPU())
	if err != nil {
		return uuid.Nil, err
	}

	for chunk := range chunkChan(sources, c.lowlevel.GetLimits().FileCountLimit) {
		files := make([]lowlevel.UploadFile, 0, c.lowlevel.GetLimits().FileCountLimit)
		defer func() {
			for _, file := range files {
				file.File.Close()
			}
		}()
		for _, pth := range chunk {
			f, err := os.Open(pth)
			if err != nil {
				return uuid.Nil, err
			}
			relPth, err := filepath.Rel(dir.Name(), pth)
			if err != nil {
				return uuid.Nil, err
			}
			files = append(files, lowlevel.UploadFile{
				Path: relPth,
				File: f,
			})
		}
		err = c.lowlevel.UploadFiles(ctx, c.orgID, revision.Data.ID, files)
		if err != nil {
			return uuid.Nil, err
		}
	}

	_, err = c.lowlevel.SealRevision(ctx, c.orgID, revision.Data.ID)
	if err != nil {
		return uuid.Nil, err
	}

	return revision.Data.ID, nil
}
