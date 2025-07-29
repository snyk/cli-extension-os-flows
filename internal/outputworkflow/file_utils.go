package outputworkflow

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

const (
	// Fileperm755 is a constant for file permissions.
	Fileperm755 fs.FileMode = 0o755 // Owner=rwx, Group=r-x, Other=r-x
	// Fileperm666 is a constant for file permissions.
	Fileperm666 fs.FileMode = 0o666 // Owner=rw-, Group=rw-, Other=rw-
)

// CreateFilePath creates the directory path for a file if it doesn't exist.
func CreateFilePath(path string) error {
	dirPath := filepath.Dir(path)
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		mkdirErr := os.MkdirAll(dirPath, Fileperm755)
		if mkdirErr != nil {
			return fmt.Errorf("failed to create directory path %s: %w", dirPath, mkdirErr)
		}
	}
	return nil
}
