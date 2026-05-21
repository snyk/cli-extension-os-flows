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

func TestHasSupportedSources_AllSupportedExtensions(t *testing.T) {
	exts := []string{".java", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".py", ".cs"}
	for _, ext := range exts {
		t.Run(ext, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, dir, "file"+ext, "// content")

			got, err := sources.HasSupportedSources(dir, nopLogger())

			require.NoError(t, err)
			assert.True(t, got, "expected %s to be recognised as supported", ext)
		})
	}
}

func TestHasSupportedSources_OnlyUnsupportedFiles_ReturnsFalse(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.go", "package main")
	writeFile(t, dir, "README.md", "# hi")
	writeFile(t, dir, "Gemfile", "source 'https://rubygems.org'")
	writeFile(t, dir, "script.rb", "puts 'hi'")
	writeFile(t, dir, "index.php", "<?php ?>")

	got, err := sources.HasSupportedSources(dir, nopLogger())

	require.NoError(t, err)
	assert.False(t, got)
}

func TestHasSupportedSources_MixedTree_ReturnsTrue(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.go", "package main")
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "frontend", "src"), 0o755))
	writeFile(t, filepath.Join(dir, "frontend", "src"), "index.ts", "export {}")

	got, err := sources.HasSupportedSources(dir, nopLogger())

	require.NoError(t, err)
	assert.True(t, got)
}

func TestHasSupportedSources_RespectsGitignore(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ".gitignore", "ignored/\n")
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "ignored"), 0o755))
	writeFile(t, filepath.Join(dir, "ignored"), "App.java", "class App {}")
	writeFile(t, dir, "main.go", "package main")

	got, err := sources.HasSupportedSources(dir, nopLogger())

	require.NoError(t, err)
	assert.False(t, got, "supported file under an ignored path must not count")
}

func TestHasSupportedSources_NonexistentPath_ReturnsError(t *testing.T) {
	got, err := sources.HasSupportedSources("/this/path/should/not/exist/ever", nopLogger())

	require.Error(t, err)
	assert.False(t, got)
}

func writeFile(t *testing.T, dir, name, body string) {
	t.Helper()
	p := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
}
