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
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

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

// NewClientFromInvocationContext creates a new file upload client from a workflow.InvocationContext.
// This is a convenience function that extracts the necessary configuration and HTTP client
// from the invocation context.
func NewClientFromInvocationContext(ictx workflow.InvocationContext, orgID uuid.UUID) Client {
	cfg := ictx.GetConfiguration()
	return NewClient(
		ictx.GetNetworkAccess().GetHttpClient(),
		Config{
			BaseURL:   cfg.GetString(configuration.API_URL),
			OrgID:     orgID,
			IsFedRamp: cfg.GetBool(configuration.IS_FEDRAMP),
		},
	)
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

// preparedFile represents a file that has been opened and validated for upload.
type preparedFile struct {
	uploadFile uploadrevision.UploadFile
	size       int64
}

func (c *HTTPClient) uploadPaths(ctx context.Context, revID RevisionID, rootPath string, paths []string) error {
	limits := c.uploadRevisionSealableClient.GetLimits()
	batch := newUploadBatch(limits.FileCountLimit)

	defer batch.closeRemainingFiles()

	for _, pth := range paths {
		prepared, skip, err := c.prepareFileForUpload(pth, rootPath, limits)
		if err != nil {
			return err
		}
		if skip {
			continue
		}

		// Flush batch if adding this file would exceed limits
		if batch.wouldExceedLimits(prepared.size, limits) {
			if err := c.flushBatch(ctx, revID, batch); err != nil {
				prepared.uploadFile.File.Close()
				return err
			}
		}

		batch.addFile(prepared)
	}

	// Upload any remaining files
	if err := c.flushBatch(ctx, revID, batch); err != nil {
		return err
	}

	// If no files were uploaded at all, return an error
	if batch.totalUploaded == 0 && len(paths) > 0 {
		return uploadrevision.ErrNoFilesProvided
	}

	return nil
}

// prepareFileForUpload opens, validates, and prepares a file for upload.
// Returns the prepared file, whether to skip it, and any error.
func (c *HTTPClient) prepareFileForUpload(pth, rootPath string, limits uploadrevision.Limits) (*preparedFile, bool, error) {
	relPth, err := filepath.Rel(rootPath, pth)
	if err != nil {
		return nil, false, fmt.Errorf("failed to get relative path for %s: %w", pth, err)
	}

	f, err := os.Open(pth)
	if err != nil {
		return nil, false, fmt.Errorf("failed to open file %s: %w", pth, err)
	}

	fstat, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, false, fmt.Errorf("failed to stat file %s: %w", pth, err)
	}

	if fstat.Size() > limits.FileSizeLimit {
		f.Close()
		return nil, true, nil
	}

	return &preparedFile{
		uploadFile: uploadrevision.UploadFile{
			Path: relPth,
			File: f,
		},
		size: fstat.Size(),
	}, false, nil
}

// uploadBatch manages a batch of files for upload.
type uploadBatch struct {
	files         []uploadrevision.UploadFile
	currentSize   int64
	totalUploaded int
	initialCap    int
}

func newUploadBatch(capacity int) *uploadBatch {
	return &uploadBatch{
		files:      make([]uploadrevision.UploadFile, 0, capacity),
		initialCap: capacity,
	}
}

func (b *uploadBatch) addFile(prepared *preparedFile) {
	b.files = append(b.files, prepared.uploadFile)
	b.currentSize += prepared.size
}

func (b *uploadBatch) wouldExceedLimits(fileSize int64, limits uploadrevision.Limits) bool {
	wouldExceedCount := len(b.files) >= limits.FileCountLimit
	wouldExceedSize := b.currentSize+fileSize > limits.TotalPayloadSizeLimit
	return wouldExceedCount || wouldExceedSize
}

func (b *uploadBatch) reset() {
	b.files = make([]uploadrevision.UploadFile, 0, b.initialCap)
	b.currentSize = 0
}

func (b *uploadBatch) isEmpty() bool {
	return len(b.files) == 0
}

func (b *uploadBatch) closeRemainingFiles() {
	for _, file := range b.files {
		file.File.Close()
	}
}

// flushBatch uploads the current batch and resets it.
func (c *HTTPClient) flushBatch(ctx context.Context, revID RevisionID, batch *uploadBatch) error {
	if batch.isEmpty() {
		return nil
	}

	err := c.uploadRevisionSealableClient.UploadFiles(ctx, c.cfg.OrgID, revID, batch.files)
	if err != nil {
		return fmt.Errorf("failed to upload files: %w", err)
	}

	// Close files in the uploaded batch
	for _, file := range batch.files {
		file.File.Close()
	}

	batch.totalUploaded += len(batch.files)
	batch.reset()
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
