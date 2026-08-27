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

// SaveJSONToFile writes contents to path as the --json-file-output file,
// creating the parent directory when missing and terminating the file with a
// newline. Failures are reported on stderr and swallowed rather than returned,
// matching the legacy CLI's saveJsonToFileCreatingDirectoryIfRequired.
func SaveJSONToFile(path string, contents []byte) {
	if err := CreateFilePath(path); err != nil {
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintf(os.Stderr, "could not create directory %s\n", filepath.Dir(path))
		return
	}

	if err := os.WriteFile(path, append(contents, '\n'), fileperm666); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
