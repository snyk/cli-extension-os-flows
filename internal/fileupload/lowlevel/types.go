package lowlevel_fileupload

import (
	"io/fs"
)

type UploadRevisionRequestAttributes struct {
	RevisionType string `json:"revision_type"`
}

type UploadRevisionRequestData struct {
	Attributes UploadRevisionRequestAttributes `json:"attributes"`
	Type       string                          `json:"type"`
}

type UploadRevisionRequestBody struct {
	Data UploadRevisionRequestData `json:"data"`
}

type UploadRevisionResponseAttributes struct {
	RevisionType string `json:"revision_type"`
	Sealed       bool   `json:"sealed"`
}

type UploadRevisionResponseData struct {
	ID         string                           `json:"id"`
	Type       string                           `json:"type"`
	Attributes UploadRevisionResponseAttributes `json:"attributes"`
}

type UploadRevisionResponseBody struct {
	Data UploadRevisionResponseData `json:"data"`
}

type ResponseError struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type ErrorResponseBody struct {
	Errors []ResponseError `json:"errors"`
}

type UploadFile struct {
	Path string // The name to use for the file in the upload
	File fs.File
}
