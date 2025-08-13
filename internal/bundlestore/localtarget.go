package bundlestore

// LocalTarget satisfies the scan.Target interface required for uploading source code.
type LocalTarget struct {
	path string
}

// GetPath returns the path of the LocalTarget.
func (lt LocalTarget) GetPath() string {
	return lt.path
}
