package outputworkflow

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

const (
	// fileperm755 is the permission for creating directories: Owner=rwx, Group=r-x, Other=r-x.
	fileperm755 fs.FileMode = 0o755
	// fileperm666 is the permission file output: Owner=rw-, Group=rw-, Other=rw-.
	fileperm666 fs.FileMode = 0o666
)

// CreateFilePath creates the directory path for a file if it doesn't exist.
func CreateFilePath(path string) error {
	dirPath := filepath.Dir(path)
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		mkdirErr := os.MkdirAll(dirPath, fileperm755)
		if mkdirErr != nil {
			return fmt.Errorf("failed to create directory path %s: %w", dirPath, mkdirErr)
		}
	}
	return nil
}
