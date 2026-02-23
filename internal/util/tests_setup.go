package util

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/constants"
)

// LoadedFile is a utility struct used for passing
// a file path and it's content in tests.
type LoadedFile struct {
	Path      string
	Content   string
	Size      *int64
	IsSymlink bool
}

// CreateTmpFiles is an utility function used to create temporary files in tests.
func CreateTmpFiles(t *testing.T, files []LoadedFile) (dir *os.File) {
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

		if file.IsSymlink {
			if err := os.Symlink(file.Content, fullPath); err != nil {
				panic(err)
			}
			continue
		}

		f, err := os.Create(fullPath)
		if err != nil {
			panic(err)
		}

		if _, err = f.WriteString(file.Content); err != nil {
			f.Close()
			panic(err)
		}

		if file.Size != nil {
			if err = f.Truncate(*file.Size); err != nil {
				f.Close()
				panic(err)
			}
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

// CreateTempDirWithUvLock creates a temporary directory containing a uv.lock file for testing.
func CreateTempDirWithUvLock(t *testing.T) string {
	t.Helper()

	dir, err := os.MkdirTemp("", "snyktest-uv")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })

	uvLockPath := filepath.Join(dir, constants.UvLockFileName)
	fd, err := os.Create(uvLockPath)
	require.NoError(t, err)
	defer fd.Close()

	_, err = fd.WriteString("# uv.lock test file\n")
	require.NoError(t, err)

	return dir
}
