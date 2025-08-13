package fileupload

import (
	"github.com/snyk/cli-extension-os-flows/internal/fileupload/filters"
	"github.com/snyk/cli-extension-os-flows/internal/fileupload/uploadrevision"
)

// Option allows customizing the Client during construction.
type Option func(*HTTPClient)

// WithUploadRevisionSealableClient allows injecting a custom low-level client (primarily for testing).
func WithUploadRevisionSealableClient(client uploadrevision.SealableClient) Option {
	return func(c *HTTPClient) {
		c.uploadRevisionSealableClient = client
	}
}

// WithFiltersClient allows injecting a custom low-level client (primarily for testing).
func WithFiltersClient(client filters.Client) Option {
	return func(c *HTTPClient) {
		c.filtersClient = client
	}
}
