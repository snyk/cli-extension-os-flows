package outputworkflow_test

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/outputworkflow"
)

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	require.NoError(t, err)

	orig := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = orig }()

	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, copyErr := io.Copy(&buf, r)
		if copyErr != nil {
			buf.WriteString(copyErr.Error())
		}
		done <- buf.String()
	}()

	fn()

	require.NoError(t, w.Close())
	captured := <-done
	require.NoError(t, r.Close())

	return captured
}

func Test_SaveJSONToFile_CreatesMissingParentDirectory(t *testing.T) {
	tests := []struct {
		name    string
		relPath string
	}{
		{name: "missing parent directory", relPath: filepath.Join("target", "site", "results.json")},
		{name: "deeply nested missing parents", relPath: filepath.Join("a", "b", "c", "d", "results.json")},
		{name: "existing parent directory", relPath: "results.json"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), tc.relPath)

			stderr := captureStderr(t, func() {
				outputworkflow.SaveJSONToFile(path, []byte(`{"ok":true}`))
			})
			assert.Empty(t, stderr)

			written, err := os.ReadFile(path)
			require.NoError(t, err)

			var parsed struct {
				Ok bool `json:"ok"`
			}
			require.NoError(t, json.Unmarshal(written, &parsed))
			assert.True(t, parsed.Ok)

			assert.Equal(t, byte('\n'), written[len(written)-1])

			reference := filepath.Join(t.TempDir(), "reference.json")
			//nolint:gosec // Reference file for the permission comparison, not output.
			require.NoError(t, os.WriteFile(reference, []byte("{}"), 0o666))
			refInfo, err := os.Stat(reference)
			require.NoError(t, err)
			gotInfo, err := os.Stat(path)
			require.NoError(t, err)
			assert.Equal(t, refInfo.Mode().Perm(), gotInfo.Mode().Perm())
		})
	}
}

func Test_SaveJSONToFile_SwallowsFailures(t *testing.T) {
	tests := []struct {
		name          string
		setup         func(t *testing.T, dir string) string
		wantStderr    []string
		notWantStderr []string
	}{
		{
			name: "parent path component is a regular file",
			setup: func(t *testing.T, dir string) string {
				t.Helper()
				blocker := filepath.Join(dir, "blocker")
				require.NoError(t, os.WriteFile(blocker, []byte("not a directory"), 0o600))
				return filepath.Join(blocker, "results.json")
			},
			wantStderr:    []string{"results.json"},
			notWantStderr: []string{"could not create directory"},
		},
		{
			name: "parent directory cannot be created",
			setup: func(t *testing.T, dir string) string {
				t.Helper()
				if runtime.GOOS == "windows" {
					t.Skip("directory permissions are not enforced the same way on windows")
				}
				if os.Geteuid() == 0 {
					t.Skip("root bypasses directory permissions")
				}
				readOnly := filepath.Join(dir, "read-only")
				require.NoError(t, os.Mkdir(readOnly, 0o555))
				return filepath.Join(readOnly, "target", "results.json")
			},
			wantStderr: []string{"could not create directory"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := tc.setup(t, t.TempDir())

			stderr := captureStderr(t, func() {
				outputworkflow.SaveJSONToFile(path, []byte(`{"ok":true}`))
			})

			assert.NoFileExists(t, path)

			for _, want := range tc.wantStderr {
				assert.Contains(t, stderr, want)
			}
			for _, notWant := range tc.notWantStderr {
				assert.NotContains(t, stderr, notWant)
			}
		})
	}
}
