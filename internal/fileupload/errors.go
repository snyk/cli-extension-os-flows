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

// SpecialFileError indicates a path points to a special file (device, pipe, socket, etc.) instead of a regular file.
type SpecialFileError = uploadrevision.SpecialFileError

// HTTPError indicates an HTTP request/response error.
type HTTPError = uploadrevision.HTTPError

// MultipartError indicates an issue with multipart request handling.
type MultipartError = uploadrevision.MultipartError
