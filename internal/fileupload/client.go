package fileupload

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"

	"github.com/google/uuid"
	"github.com/puzpuzpuz/xsync"

	listsources "github.com/snyk/cli-extension-os-flows/internal/files"
	"github.com/snyk/cli-extension-os-flows/internal/fileupload/filters"
	"github.com/snyk/cli-extension-os-flows/internal/fileupload/uploadrevision"
)

// Config contains configuration for the file upload client.
type Config struct {
	BaseURL   string
	OrgID     OrgID
	IsFedRamp bool
}

// HTTPClient provides high-level file upload functionality.
type HTTPClient struct {
	uploadRevisionSealableClient uploadrevision.SealableClient
	filtersClient                filters.Client
	cfg                          Config
	filters                      Filters
}

// Client defines the interface for the high level file upload client.
type Client interface {
	CreateRevisionFromPaths(ctx context.Context, paths []string, opts UploadOptions) (RevisionID, error)
	CreateRevisionFromDir(ctx context.Context, dirPath string, opts UploadOptions) (RevisionID, error)
	CreateRevisionFromFile(ctx context.Context, filePath string, opts UploadOptions) (RevisionID, error)
}

var _ Client = (*HTTPClient)(nil)

// NewClient creates a new high-level file upload client.
func NewClient(httpClient *http.Client, cfg Config, opts ...Option) *HTTPClient {
	client := &HTTPClient{
		cfg: cfg,
		filters: Filters{
			supportedExtensions:  xsync.NewMapOf[bool](),
			supportedConfigFiles: xsync.NewMapOf[bool](),
		},
	}

	for _, opt := range opts {
		opt(client)
	}

	if client.uploadRevisionSealableClient == nil {
		client.uploadRevisionSealableClient = uploadrevision.NewClient(uploadrevision.Config{
			BaseURL: cfg.BaseURL,
		}, uploadrevision.WithHTTPClient(httpClient))
	}

	if client.filtersClient == nil {
		client.filtersClient = filters.NewDeeproxyClient(filters.Config{
			BaseURL:   cfg.BaseURL,
			IsFedRamp: cfg.IsFedRamp,
		}, filters.WithHTTPClient(httpClient))
	}

	return client
}

func (c *HTTPClient) loadFilters(ctx context.Context) error {
	c.filters.once.Do(func() {
		filtersResp, err := c.filtersClient.GetFilters(ctx, c.cfg.OrgID)
		if err != nil {
			c.filters.initErr = err
			return
		}

		for _, ext := range filtersResp.Extensions {
			c.filters.supportedExtensions.Store(ext, true)
		}
		for _, configFile := range filtersResp.ConfigFiles {
			// .gitignore and .dcignore should not be uploaded
			// (https://github.com/snyk/code-client/blob/d6f6a2ce4c14cb4b05aa03fb9f03533d8cf6ca4a/src/files.ts#L138)
			if configFile == ".gitignore" || configFile == ".dcignore" {
				continue
			}
			c.filters.supportedConfigFiles.Store(configFile, true)
		}
	})
	return c.filters.initErr
}

// createFileFilter creates a filter function based on the current filtering configuration.
func (c *HTTPClient) createFileFilter(ctx context.Context) (func(string) bool, error) {
	if err := c.loadFilters(ctx); err != nil {
		return nil, fmt.Errorf("failed to load deeproxy filters: %w", err)
	}

	return func(path string) bool {
		fileExt := filepath.Ext(path)
		fileName := filepath.Base(path)
		_, isSupportedExtension := c.filters.supportedExtensions.Load(fileExt)
		_, isSupportedConfigFile := c.filters.supportedConfigFiles.Load(fileName)
		return isSupportedExtension || isSupportedConfigFile
	}, nil
}

func (c *HTTPClient) uploadPaths(ctx context.Context, revID RevisionID, rootPath string, paths []string) error {
	files := make([]uploadrevision.UploadFile, 0, c.uploadRevisionSealableClient.GetLimits().FileCountLimit)
	defer func() {
		for _, file := range files {
			file.File.Close()
		}
	}()

	for _, pth := range paths {
		relPth, err := filepath.Rel(rootPath, pth)
		if err != nil {
			return fmt.Errorf("failed to get relative path for %s: %w", pth, err)
		}

		f, err := os.Open(pth)
		if err != nil {
			return fmt.Errorf("failed to open file %s: %w", pth, err)
		}

		fstat, err := f.Stat()
		if err != nil {
			return fmt.Errorf("failed to stat file %s: %w", pth, err)
		}

		// TODO: This behavior should be configurable through options.
		if fstat.Size() > c.uploadRevisionSealableClient.GetLimits().FileSizeLimit {
			f.Close()
			//nolint:forbidigo // Temporarily use fmt to print warning.
			fmt.Printf("skipping file exceeding size limit %s\n", pth)
			continue
		}

		files = append(files, uploadrevision.UploadFile{
			Path: relPth,
			File: f,
		})
	}

	err := c.uploadRevisionSealableClient.UploadFiles(ctx, c.cfg.OrgID, revID, files)
	if err != nil {
		return fmt.Errorf("failed to upload files: %w", err)
	}

	return nil
}

// addPathsToRevision adds multiple file paths to an existing revision.
func (c *HTTPClient) addPathsToRevision(ctx context.Context, revisionID RevisionID, rootPath string, pathsChan <-chan string, opts UploadOptions) error {
	var chunks <-chan []string

	if opts.SkipFiltering {
		chunks = chunkChan(pathsChan, c.uploadRevisionSealableClient.GetLimits().FileCountLimit)
	} else {
		filter, err := c.createFileFilter(ctx)
		if err != nil {
			return err
		}
		chunks = chunkChanFiltered(pathsChan, c.uploadRevisionSealableClient.GetLimits().FileCountLimit, filter)
	}

	for chunk := range chunks {
		err := c.uploadPaths(ctx, revisionID, rootPath, chunk)
		if err != nil {
			return err
		}
	}

	return nil
}

// createRevision creates a new revision and returns its ID.
func (c *HTTPClient) createRevision(ctx context.Context) (RevisionID, error) {
	revision, err := c.uploadRevisionSealableClient.CreateRevision(ctx, c.cfg.OrgID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to create revision: %w", err)
	}
	return revision.Data.ID, nil
}

// addFileToRevision adds a single file to an existing revision.
func (c *HTTPClient) addFileToRevision(ctx context.Context, revisionID RevisionID, filePath string, opts UploadOptions) error {
	writableChan := make(chan string, 1)
	writableChan <- filePath
	close(writableChan)

	return c.addPathsToRevision(ctx, revisionID, filepath.Dir(filePath), writableChan, opts)
}

// addDirToRevision adds a directory and all its contents to an existing revision.
func (c *HTTPClient) addDirToRevision(ctx context.Context, revisionID RevisionID, dirPath string, opts UploadOptions) error {
	sources, err := listsources.ForPath(dirPath, nil, runtime.NumCPU())
	if err != nil {
		return fmt.Errorf("failed to list files in directory %s: %w", dirPath, err)
	}

	return c.addPathsToRevision(ctx, revisionID, dirPath, sources, opts)
}

// sealRevision seals a revision, making it immutable.
func (c *HTTPClient) sealRevision(ctx context.Context, revisionID RevisionID) error {
	_, err := c.uploadRevisionSealableClient.SealRevision(ctx, c.cfg.OrgID, revisionID)
	if err != nil {
		return fmt.Errorf("failed to seal revision: %w", err)
	}
	return nil
}

// CreateRevisionFromPaths uploads multiple paths (files or directories), returning a revision ID.
// This is a convenience method that creates, uploads, and seals a revision.
func (c *HTTPClient) CreateRevisionFromPaths(ctx context.Context, paths []string, opts UploadOptions) (RevisionID, error) {
	revisionID, err := c.createRevision(ctx)
	if err != nil {
		return uuid.Nil, err
	}

	for _, pth := range paths {
		info, err := os.Stat(pth)
		if err != nil {
			return uuid.Nil, uploadrevision.NewFileAccessError(pth, err)
		}

		if info.IsDir() {
			if err := c.addDirToRevision(ctx, revisionID, pth, opts); err != nil {
				return uuid.Nil, fmt.Errorf("failed to add directory %s: %w", pth, err)
			}
		} else {
			if err := c.addFileToRevision(ctx, revisionID, pth, opts); err != nil {
				return uuid.Nil, fmt.Errorf("failed to add file %s: %w", pth, err)
			}
		}
	}

	if err := c.sealRevision(ctx, revisionID); err != nil {
		return uuid.Nil, err
	}

	return revisionID, nil
}

// CreateRevisionFromDir uploads a directory and all its contents, returning a revision ID.
// This is a convenience method for validating the directory path and calling CreateRevisionFromPaths with a single directory path.
func (c *HTTPClient) CreateRevisionFromDir(ctx context.Context, dirPath string, opts UploadOptions) (RevisionID, error) {
	info, err := os.Stat(dirPath)
	if err != nil {
		return uuid.Nil, uploadrevision.NewFileAccessError(dirPath, err)
	}

	if !info.IsDir() {
		return uuid.Nil, fmt.Errorf("the provided path is not a directory: %s", dirPath)
	}

	return c.CreateRevisionFromPaths(ctx, []string{dirPath}, opts)
}

// CreateRevisionFromFile uploads a single file, returning a revision ID.
// This is a convenience method for validating the file path and calling CreateRevisionFromPaths with a single file path.
func (c *HTTPClient) CreateRevisionFromFile(ctx context.Context, filePath string, opts UploadOptions) (RevisionID, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		return uuid.Nil, uploadrevision.NewFileAccessError(filePath, err)
	}

	if !info.Mode().IsRegular() {
		return uuid.Nil, fmt.Errorf("the provided path is not a regular file: %s", filePath)
	}

	return c.CreateRevisionFromPaths(ctx, []string{filePath}, opts)
}
