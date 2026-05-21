package sources_test

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/reachability/sources"
)

func nopLogger() *zerolog.Logger {
	l := zerolog.New(io.Discard)
	return &l
}

func TestHasSupportedSources_EmptyDir_ReturnsFalse(t *testing.T) {
	dir := t.TempDir()

	got, err := sources.HasSupportedSources(dir, nopLogger())

	require.NoError(t, err)
	assert.False(t, got)
}

func TestHasSupportedSources_SingleJavaFile_ReturnsTrue(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "App.java", "class App {}")

	got, err := sources.HasSupportedSources(dir, nopLogger())

	require.NoError(t, err)
	assert.True(t, got)
}

func writeFile(t *testing.T, dir, name, body string) {
	t.Helper()
	p := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
}
