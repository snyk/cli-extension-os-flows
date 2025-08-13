package fileupload

import (
	"sync"

	"github.com/puzpuzpuz/xsync"

	"github.com/snyk/cli-extension-os-flows/internal/fileupload/uploadrevision"
)

// OrgID represents an organization identifier.
type OrgID = uploadrevision.OrgID

// RevisionID represents a revision identifier.
type RevisionID = uploadrevision.RevisionID

// Filters holds the filtering configuration for file uploads with thread-safe maps.
type Filters struct {
	supportedExtensions  *xsync.MapOf[string, bool]
	supportedConfigFiles *xsync.MapOf[string, bool]
	once                 sync.Once
	initErr              error
}

// UploadOptions configures the behavior of file upload operations.
type UploadOptions struct {
	SkipFiltering bool
}
