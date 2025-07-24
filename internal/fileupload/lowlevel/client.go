package lowlevel_fileupload //nolint:revive // underscore naming is intentional for this internal package

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"

	"github.com/google/uuid"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
)

// Client defines the interface for file upload API operations.
type Client interface {
	CreateRevision(ctx context.Context, orgID OrgID) (*UploadRevisionResponseBody, error)
	UploadFiles(ctx context.Context, orgID OrgID, revisionID RevisionID, files []UploadFile) error
	SealRevision(ctx context.Context, orgID OrgID, revisionID RevisionID) (*SealUploadRevisionResponseBody, error)
}

// This will force go to complain if the type doesn't satisfy the interface.
var _ Client = (*HTTPClient)(nil)

// Config contains configuration for the file upload client.
type Config struct {
	BaseURL string
}

// HTTPClient implements the Client interface for file upload operations via HTTP API.
type HTTPClient struct {
	cfg        Config
	httpClient *http.Client
}

// APIVersion specifies the API version to use for requests.
const APIVersion = "2024-10-15"

// FileSizeLimit specifies the maximum allowed file size in bytes.
const FileSizeLimit = 50_000_000 // arbitrary number, chosen to support max size of SBOMs

// FileCountLimit specifies the maximum number of files allowed in a single upload.
const FileCountLimit = 100 // arbitrary number, will need to be re-evaluated

// ContentType is the HTTP header name for content type.
const ContentType = "Content-Type"

// NewClient creates a new file upload client with the given configuration and options.
func NewClient(cfg Config, opts ...Opt) *HTTPClient {
	c := HTTPClient{cfg, http.DefaultClient}

	for _, opt := range opts {
		opt(&c)
	}

	return &c
}

// CreateRevision creates a new upload revision for the specified organization.
func (c *HTTPClient) CreateRevision(ctx context.Context, orgID OrgID) (*UploadRevisionResponseBody, error) {
	if orgID == uuid.Nil {
		return nil, ErrEmptyOrgID
	}

	body := UploadRevisionRequestBody{
		Data: UploadRevisionRequestData{
			Attributes: UploadRevisionRequestAttributes{
				RevisionType: RevisionTypeSnapshot,
			},
			Type: ResourceTypeUploadRevision,
		},
	}
	buff := bytes.NewBuffer(nil)
	if err := json.NewEncoder(buff).Encode(body); err != nil {
		return nil, fmt.Errorf("failed to encode request body: %w", err)
	}

	url := fmt.Sprintf("%s/hidden/orgs/%s/upload_revisions?version=%s", c.cfg.BaseURL, orgID, APIVersion)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, buff)
	if err != nil {
		return nil, fmt.Errorf("failed to create request body: %w", err)
	}
	req.Header.Set(ContentType, "application/vnd.api+json")

	res, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making create revision request: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusCreated {
		return nil, c.handleUnexpectedStatusCodes(res.Body, res.StatusCode, res.Status, "create upload revision")
	}

	var respBody UploadRevisionResponseBody
	if err := json.NewDecoder(res.Body).Decode(&respBody); err != nil {
		return nil, fmt.Errorf("failed to decode upload revision response: %w", err)
	}

	return &respBody, nil
}

// UploadFiles uploads the provided files to the specified revision. It will not close the file descriptors.
func (c *HTTPClient) UploadFiles(ctx context.Context, orgID OrgID, revisionID RevisionID, files []UploadFile) error {
	if orgID == uuid.Nil {
		return ErrEmptyOrgID
	}

	if revisionID == uuid.Nil {
		return ErrEmptyRevisionID
	}

	if len(files) > FileCountLimit {
		return NewFileCountLimitError(len(files), FileCountLimit)
	}

	if len(files) == 0 {
		return ErrNoFilesProvided
	}

	for _, file := range files {
		fileInfo, err := file.File.Stat()
		if err != nil {
			return NewFileAccessError(file.Path, err)
		}

		if fileInfo.IsDir() {
			return NewDirectoryError(file.Path)
		}

		if fileInfo.Size() > FileSizeLimit {
			return NewFileSizeLimitError(file.Path, fileInfo.Size(), FileSizeLimit)
		}
	}

	// Create pipe for streaming multipart data
	pReader, pWriter := io.Pipe()
	mpartWriter := multipart.NewWriter(pWriter)

	// Start goroutine to write multipart data
	go c.streamFilesToPipe(pWriter, mpartWriter, files)

	// Create HTTP request with streaming body
	url := fmt.Sprintf("%s/hidden/orgs/%s/upload_revisions/%s/files?version=%s", c.cfg.BaseURL, orgID, revisionID, APIVersion)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, pReader)
	if err != nil {
		pReader.Close()
		return fmt.Errorf("failed to create upload files request: %w", err)
	}

	req.Header.Set(ContentType, mpartWriter.FormDataContentType())

	res, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("error making upload files request: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusNoContent {
		return c.handleUnexpectedStatusCodes(res.Body, res.StatusCode, res.Status, "upload files")
	}

	return nil
}

func (c *HTTPClient) streamFilesToPipe(pWriter *io.PipeWriter, mpartWriter *multipart.Writer, files []UploadFile) {
	var streamError error
	defer func() {
		pWriter.CloseWithError(streamError)
	}()
	defer mpartWriter.Close()

	for _, file := range files {
		// Create form file part
		part, err := mpartWriter.CreateFormFile(file.Path, file.Path)
		if err != nil {
			streamError = NewMultipartError(file.Path, err)
			return
		}

		_, err = io.Copy(part, file.File)
		if err != nil {
			streamError = fmt.Errorf("failed to copy file content for %s: %w", file.Path, err)
			return
		}
	}
}

// SealRevision seals the specified upload revision, marking it as complete.
func (c *HTTPClient) SealRevision(ctx context.Context, orgID OrgID, revisionID RevisionID) (*SealUploadRevisionResponseBody, error) {
	if orgID == uuid.Nil {
		return nil, ErrEmptyOrgID
	}

	if revisionID == uuid.Nil {
		return nil, ErrEmptyRevisionID
	}

	body := SealUploadRevisionRequestBody{
		Data: SealUploadRevisionRequestData{
			ID: revisionID,
			Attributes: SealUploadRevisionRequestAttributes{
				Sealed: true,
			},
			Type: ResourceTypeUploadRevision,
		},
	}
	buff := bytes.NewBuffer(nil)
	if err := json.NewEncoder(buff).Encode(body); err != nil {
		return nil, fmt.Errorf("failed to encode request body: %w", err)
	}

	url := fmt.Sprintf("%s/hidden/orgs/%s/upload_revisions/%s?version=%s", c.cfg.BaseURL, orgID, revisionID, APIVersion)
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, url, buff)
	if err != nil {
		return nil, fmt.Errorf("failed to create request body: %w", err)
	}
	req.Header.Set(ContentType, "application/vnd.api+json")

	res, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making seal revision request: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, c.handleUnexpectedStatusCodes(res.Body, res.StatusCode, res.Status, "seal upload revision")
	}

	var respBody SealUploadRevisionResponseBody
	if err := json.NewDecoder(res.Body).Decode(&respBody); err != nil {
		return nil, fmt.Errorf("failed to decode upload revision response: %w", err)
	}

	return &respBody, nil
}

func (c *HTTPClient) handleUnexpectedStatusCodes(body io.ReadCloser, statusCode int, status, operation string) error {
	bts, err := io.ReadAll(body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if len(bts) > 0 {
		snykErrorList, parseErr := snyk_errors.FromJSONAPIErrorBytes(bts)
		if parseErr == nil && len(snykErrorList) > 0 && snykErrorList[0].Title != "" {
			errsToJoin := []error{}
			for i := range snykErrorList {
				errsToJoin = append(errsToJoin, snykErrorList[i])
			}
			return fmt.Errorf("API error during %s: %w", operation, errors.Join(errsToJoin...))
		}
	}

	return NewHTTPError(statusCode, status, operation, bts)
}
