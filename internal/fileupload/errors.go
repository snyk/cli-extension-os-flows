package fileupload

import "github.com/snyk/cli-extension-os-flows/internal/fileupload/uploadrevision"

// Aliasing uploadRevisionSealableClient errors so that they're scoped to the fileupload package as well.

// Sentinel errors for common conditions.
var (
	ErrNoFilesProvided = uploadrevision.ErrNoFilesProvided
	ErrEmptyOrgID      = uploadrevision.ErrEmptyOrgID
	ErrEmptyRevisionID = uploadrevision.ErrEmptyRevisionID
)

// FileSizeLimitError indicates a file exceeds the maximum allowed size.
type FileSizeLimitError = uploadrevision.FileSizeLimitError

// FileCountLimitError indicates too many files were provided.
type FileCountLimitError = uploadrevision.FileCountLimitError

// FileAccessError indicates a file access permission issue.
type FileAccessError = uploadrevision.FileAccessError

// DirectoryError indicates an issue with directory operations.
type DirectoryError = uploadrevision.DirectoryError

// HTTPError indicates an HTTP request/response error.
type HTTPError = uploadrevision.HTTPError

// MultipartError indicates an issue with multipart request handling.
type MultipartError = uploadrevision.MultipartError
