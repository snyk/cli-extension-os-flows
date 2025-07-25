package lowlevel_fileupload

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"

	"github.com/snyk/error-catalog-golang-public/snyk_errors"
)

type ClientInterface interface {
	CreateRevision(ctx context.Context, orgID string) (string, error)
	UploadFiles(ctx context.Context, orgID string, revisionID string, files []UploadFile) error
}

type Config struct {
	BaseURL string
}

type Client struct {
	cfg        Config
	httpClient *http.Client
}

type Revision struct{}

const API_VERSION = "2024-10-15"

const FILE_SIZE_LIMIT = 50_000_000 //arbitrary number, chosen to support max size of SBOMs

const FILE_COUNT_LIMIT = 100 // arbitrary number, will need to be re-evaluated

func NewClient(cfg Config, opts ...Opt) *Client {
	c := Client{cfg, http.DefaultClient}

	for _, opt := range opts {
		opt(&c)
	}

	return &c
}

func (c *Client) CreateRevision(ctx context.Context, orgID string) (string, error) {
	body := UploadRevisionRequestBody{
		Data: UploadRevisionRequestData{
			Attributes: UploadRevisionRequestAttributes{
				RevisionType: "snapshot",
			},
			Type: "upload_revision",
		},
	}
	buff := bytes.NewBuffer(nil)
	if err := json.NewEncoder(buff).Encode(body); err != nil {
		return "", fmt.Errorf("failed to encode request body: %w", err)
	}

	url := fmt.Sprintf("%s/hidden/orgs/%s/upload_revisions?version=%s", c.cfg.BaseURL, orgID, API_VERSION)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, buff)
	if err != nil {
		return "", fmt.Errorf("failed to create request body: %w", err)
	}
	req.Header.Set("Content-Type", "application/vnd.api+json")

	res, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("error making create revision request: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusCreated {
		return "", c.handleUnexpectedStatusCodes(res.Body, res.Status, "upload revision")
	}

	var respBody UploadRevisionResponseBody
	if err := json.NewDecoder(res.Body).Decode(&respBody); err != nil {
		return "", fmt.Errorf("failed to decode upload revision response: %w", err)
	}

	return respBody.Data.ID, nil
}

func (c *Client) UploadFiles(ctx context.Context, orgID string, revisionID string, files []UploadFile) error {
	// Validate file count
	if len(files) > FILE_COUNT_LIMIT {
		return fmt.Errorf("too many files: %d exceeds limit of %d", len(files), FILE_COUNT_LIMIT)
	}

	if len(files) == 0 {
		return fmt.Errorf("no files provided for upload")
	}

	// Validate individual file sizes and existence
	for i, file := range files {
		fileInfo, err := file.File.Stat()
		if err != nil {
			return fmt.Errorf("file %d (%s) cannot be accessed: %w", i, file.Path, err)
		}

		if fileInfo.Size() > FILE_SIZE_LIMIT {
			return fmt.Errorf("file %d (%s) size %d exceeds limit of %d bytes", i, file.Path, fileInfo.Size(), FILE_SIZE_LIMIT)
		}
	}

	// Create pipe for streaming multipart data
	pReader, pWriter := io.Pipe()
	mpartWriter := multipart.NewWriter(pWriter)

	// Start goroutine to write multipart data
	go func() {
		defer pWriter.Close()
		defer mpartWriter.Close()

		for _, file := range files {
			// Create form file part
			part, err := mpartWriter.CreateFormFile(file.Path, file.Path)
			if err != nil {
				pWriter.CloseWithError(fmt.Errorf("failed to create form file for %s: %w", file.Path, err))
				return
			}

			_, err = io.Copy(part, file.File)
			file.File.Close()
			if err != nil {
				pWriter.CloseWithError(fmt.Errorf("failed to copy file content for %s: %w", file.Path, err))
				return
			}
		}
	}()

	// Create HTTP request with streaming body
	url := fmt.Sprintf("%s/hidden/orgs/%s/upload_revisions/%s/files?version=%s", c.cfg.BaseURL, orgID, revisionID, API_VERSION)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, pReader)
	if err != nil {
		pReader.Close()
		return fmt.Errorf("failed to create upload files request: %w", err)
	}

	req.Header.Set("Content-Type", mpartWriter.FormDataContentType())

	// Execute request
	res, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("error making upload files request: %w", err)
	}
	defer res.Body.Close()

	// Handle response
	if res.StatusCode != http.StatusNoContent {
		return c.handleUnexpectedStatusCodes(res.Body, res.Status, "upload files")
	}

	return nil
}

func (c *Client) SealRevision(ctx context.Context) {
}

func (c *Client) handleUnexpectedStatusCodes(body io.ReadCloser, status string, operation string) error {
	bts, err := io.ReadAll(body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if len(bts) > 0 {
		snykErrorList, parseErr := snyk_errors.FromJSONAPIErrorBytes(bts)
		if parseErr == nil && len(snykErrorList) > 0 {
			errsToJoin := []error{}
			for i := range snykErrorList {
				errsToJoin = append(errsToJoin, snykErrorList[i])
			}
			return errors.Join(errsToJoin...)
		}
	}
	return fmt.Errorf("unsuccessful request to %s: %s", operation, status)
}
