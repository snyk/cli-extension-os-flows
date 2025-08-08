package lowlevel

import (
	"io/fs"

	"github.com/google/uuid"
)

// OrgID represents an organization identifier.
type OrgID = uuid.UUID

// RevisionID represents a revision identifier.
type RevisionID = uuid.UUID

// RevisionType represents the type of revision being created.
type RevisionType string

const (
	// RevisionTypeSnapshot represents a snapshot revision type.
	RevisionTypeSnapshot RevisionType = "snapshot"
)

// ResourceType represents the type of resource in API requests.
type ResourceType string

const (
	// ResourceTypeUploadRevision represents an upload revision resource type.
	ResourceTypeUploadRevision ResourceType = "upload_revision"
)

// UploadRevisionRequestAttributes contains the attributes for creating an upload revision.
type UploadRevisionRequestAttributes struct {
	RevisionType RevisionType `json:"revision_type"` //nolint:tagliatelle // API expects snake_case
}

// UploadRevisionRequestData contains the data payload for creating an upload revision.
type UploadRevisionRequestData struct {
	Attributes UploadRevisionRequestAttributes `json:"attributes"`
	Type       ResourceType                    `json:"type"`
}

// UploadRevisionRequestBody contains the complete request body for creating an upload revision.
type UploadRevisionRequestBody struct {
	Data UploadRevisionRequestData `json:"data"`
}

// UploadRevisionResponseAttributes contains the attributes returned when creating an upload revision.
type UploadRevisionResponseAttributes struct {
	RevisionType RevisionType `json:"revision_type"` //nolint:tagliatelle // API expects snake_case
	Sealed       bool         `json:"sealed"`
}

// UploadRevisionResponseData contains the data returned when creating an upload revision.
type UploadRevisionResponseData struct {
	ID         RevisionID                       `json:"id"`
	Type       ResourceType                     `json:"type"`
	Attributes UploadRevisionResponseAttributes `json:"attributes"`
}

// UploadRevisionResponseBody contains the complete response body when creating an upload revision.
type UploadRevisionResponseBody struct {
	Data UploadRevisionResponseData `json:"data"`
}

// SealUploadRevisionRequestAttributes contains the attributes for sealing an upload revision.
type SealUploadRevisionRequestAttributes struct {
	Sealed bool `json:"sealed"`
}

// SealUploadRevisionRequestData contains the data payload for sealing an upload revision.
type SealUploadRevisionRequestData struct {
	ID         RevisionID                          `json:"id"`
	Type       ResourceType                        `json:"type"`
	Attributes SealUploadRevisionRequestAttributes `json:"attributes"`
}

// SealUploadRevisionRequestBody contains the complete request body for sealing an upload revision.
type SealUploadRevisionRequestBody struct {
	Data SealUploadRevisionRequestData `json:"data"`
}

// SealUploadRevisionResponseAttributes contains the attributes returned when sealing an upload revision.
type SealUploadRevisionResponseAttributes struct {
	RevisionType RevisionType `json:"revision_type"` //nolint:tagliatelle // API expects snake_case
	Sealed       bool         `json:"sealed"`
}

// SealUploadRevisionResponseData contains the data returned when sealing an upload revision.
type SealUploadRevisionResponseData struct {
	ID         RevisionID                           `json:"id"`
	Type       ResourceType                         `json:"type"`
	Attributes SealUploadRevisionResponseAttributes `json:"attributes"`
}

// SealUploadRevisionResponseBody contains the complete response body when sealing an upload revision.
type SealUploadRevisionResponseBody struct {
	Data SealUploadRevisionResponseData `json:"data"`
}

// ResponseError represents an error in an API response.
type ResponseError struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

// ErrorResponseBody contains the complete error response body.
type ErrorResponseBody struct {
	Errors []ResponseError `json:"errors"`
}

// UploadFile represents a file to be uploaded, containing both the path and file handle.
type UploadFile struct {
	Path string // The name to use for the file in the upload
	File fs.File
}

const (
	// ContentType is the HTTP header name for content type.
	ContentType = "Content-Type"
	// ContentEncoding is the HTTP header name for content encoding.
	ContentEncoding = "Content-Encoding"
)

// Limits contains the limits enforced by the low level client.
type Limits struct {
	// FileCountLimit specifies the maximum number of files allowed in a single upload.
	FileCountLimit int
	// FileSizeLimit specifies the maximum allowed file size in bytes.
	FileSizeLimit int64
}
