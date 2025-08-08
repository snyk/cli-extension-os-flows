package fileupload

import "github.com/snyk/cli-extension-os-flows/internal/fileupload/lowlevel"

// Aliasing lowlevel errors so that they're scoped to the fileupload package as well

type FileSizeLimitError = lowlevel.FileSizeLimitError

type FileCountLimitError = lowlevel.FileCountLimitError

type FileAccessError = lowlevel.FileAccessError

type DirectoryError = lowlevel.DirectoryError

type HTTPError = lowlevel.HTTPError

type MultipartError = lowlevel.MultipartError
