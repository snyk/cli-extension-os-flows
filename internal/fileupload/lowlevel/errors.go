package lowlevel_fileupload //nolint:revive // underscore naming is intentional for this internal package

import (
	"errors"
	"fmt"
)

// Sentinel errors for common conditions.
var (
	ErrNoFilesProvided = errors.New("no files provided for upload")
	ErrEmptyOrgID      = errors.New("organization ID cannot be empty")
	ErrEmptyRevisionID = errors.New("revision ID cannot be empty")
)

// FileSizeLimitError indicates a file exceeds the maximum allowed size.
type FileSizeLimitError struct {
	FileName string
	FileSize int64
	Limit    int64
}

func (e *FileSizeLimitError) Error() string {
	return fmt.Sprintf("file %s size %d exceeds limit of %d bytes", e.FileName, e.FileSize, e.Limit)
}

// FileCountLimitError indicates too many files were provided.
type FileCountLimitError struct {
	Count int
	Limit int
}

func (e *FileCountLimitError) Error() string {
	return fmt.Sprintf("too many files: %d exceeds limit of %d", e.Count, e.Limit)
}

// FileAccessError indicates a file cannot be accessed or read.
type FileAccessError struct {
	FileName string
	Err      error
}

func (e *FileAccessError) Error() string {
	return fmt.Sprintf("file %s cannot be accessed: %v", e.FileName, e.Err)
}

func (e *FileAccessError) Unwrap() error {
	return e.Err
}

// DirectoryError indicates a path points to a directory instead of a file.
type DirectoryError struct {
	Path string
}

func (e *DirectoryError) Error() string {
	return fmt.Sprintf("path %s is a directory, not a file", e.Path)
}

// HTTPError represents an HTTP error response.
type HTTPError struct {
	StatusCode int
	Status     string
	Operation  string
	Body       []byte
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("unsuccessful request to %s: %s", e.Operation, e.Status)
}

// MultipartError indicates an error creating multipart form data.
type MultipartError struct {
	FileName string
	Err      error
}

func (e *MultipartError) Error() string {
	return fmt.Sprintf("failed to create multipart form for %s: %v", e.FileName, e.Err)
}

func (e *MultipartError) Unwrap() error {
	return e.Err
}

// NewFileSizeLimitError creates a new FileSizeLimitError with the given parameters.
func NewFileSizeLimitError(fileName string, fileSize, limit int64) *FileSizeLimitError {
	return &FileSizeLimitError{
		FileName: fileName,
		FileSize: fileSize,
		Limit:    limit,
	}
}

// NewFileCountLimitError creates a new FileCountLimitError with the given parameters.
func NewFileCountLimitError(count, limit int) *FileCountLimitError {
	return &FileCountLimitError{
		Count: count,
		Limit: limit,
	}
}

// NewFileAccessError creates a new FileAccessError with the given parameters.
func NewFileAccessError(fileName string, err error) *FileAccessError {
	return &FileAccessError{
		FileName: fileName,
		Err:      err,
	}
}

// NewDirectoryError creates a new DirectoryError with the given path.
func NewDirectoryError(path string) *DirectoryError {
	return &DirectoryError{
		Path: path,
	}
}

// NewHTTPError creates a new HTTPError with the given parameters.
func NewHTTPError(statusCode int, status, operation string, body []byte) *HTTPError {
	return &HTTPError{
		StatusCode: statusCode,
		Status:     status,
		Operation:  operation,
		Body:       body,
	}
}

// NewMultipartError creates a new MultipartError with the given parameters.
func NewMultipartError(fileName string, err error) *MultipartError {
	return &MultipartError{
		FileName: fileName,
		Err:      err,
	}
}
