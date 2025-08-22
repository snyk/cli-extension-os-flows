package util

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/snyk/cli-extension-os-flows/internal/fileupload/uploadrevision"
)

// CreateTmpFiles is an utility function used to create temporary files in tests.
func CreateTmpFiles(t *testing.T, files []uploadrevision.LoadedFile) (dir *os.File) {
	t.Helper()

	tempDir := t.TempDir()
	dir, err := os.Open(tempDir)
	if err != nil {
		panic(err)
	}

	for _, file := range files {
		fullPath := filepath.Join(tempDir, file.Path)

		parentDir := filepath.Dir(fullPath)
		if err := os.MkdirAll(parentDir, 0o755); err != nil {
			panic(err)
		}

		f, err := os.Create(fullPath)
		if err != nil {
			panic(err)
		}

		if _, err := f.WriteString(file.Content); err != nil {
			f.Close()
			panic(err)
		}
		f.Close()
	}

	t.Cleanup(func() {
		if dir != nil {
			dir.Close()
		}
	})

	return dir
}
