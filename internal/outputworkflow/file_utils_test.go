package outputworkflow_test

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
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
