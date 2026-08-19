package sources_test

import (
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	gafmocks "github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/utils"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/reachability/sources"
)

func nopLogger() *zerolog.Logger {
	l := zerolog.New(io.Discard)
	return &l
}

func testIctx(t *testing.T, config configuration.Configuration) workflow.InvocationContext {
	t.Helper()
	logger := nopLogger()
	if config == nil {
		config = configuration.New()
	}

	ictx := gafmocks.NewMockInvocationContext(gomock.NewController(t))
	ictx.EXPECT().GetEnhancedLogger().Return(logger).AnyTimes()
	ictx.EXPECT().GetFileFilter(gomock.Any(), gomock.Any()).DoAndReturn(
		func(path string, options ...utils.FileFilterOption) *utils.FileFilter {
			return utils.NewFileFilter(path, logger, append([]utils.FileFilterOption{utils.WithConfig(config)}, options...)...)
		},
	).AnyTimes()
	return ictx
}

func TestHasSupportedSources_EmptyDir_ReturnsFalse(t *testing.T) {
	dir := t.TempDir()

	got, err := sources.HasSupportedSources(testIctx(t, nil), dir)

	require.NoError(t, err)
	assert.False(t, got)
}

func TestHasSupportedSources_SingleJavaFile_ReturnsTrue(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "App.java", "class App {}")

	got, err := sources.HasSupportedSources(testIctx(t, nil), dir)

	require.NoError(t, err)
	assert.True(t, got)
}

func TestHasSupportedSources_AllSupportedExtensions(t *testing.T) {
	for lang, exts := range sources.SupportedExtensionsByLanguage {
		for _, ext := range exts {
			t.Run(lang+"/"+ext, func(t *testing.T) {
				dir := t.TempDir()
				writeFile(t, dir, "file"+ext, "// content")

				got, err := sources.HasSupportedSources(testIctx(t, nil), dir)

				require.NoError(t, err)
				assert.True(t, got, "expected %s (%s) to be recognized as supported", ext, lang)
			})
		}
	}
}

func TestHasSupportedSources_OnlyUnsupportedFiles_ReturnsFalse(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.go", "package main")
	writeFile(t, dir, "README.md", "# hi")
	writeFile(t, dir, "Gemfile", "source 'https://rubygems.org'")
	writeFile(t, dir, "script.rb", "puts 'hi'")
	writeFile(t, dir, "index.php", "<?php ?>")

	got, err := sources.HasSupportedSources(testIctx(t, nil), dir)

	require.NoError(t, err)
	assert.False(t, got)
}

func TestHasSupportedSources_MixedTree_ReturnsTrue(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.go", "package main")
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "frontend", "src"), 0o755))
	writeFile(t, filepath.Join(dir, "frontend", "src"), "index.ts", "export {}")

	got, err := sources.HasSupportedSources(testIctx(t, nil), dir)

	require.NoError(t, err)
	assert.True(t, got)
}

func TestHasSupportedSources_RespectsGitignore(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ".gitignore", "ignored/\n")
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "ignored"), 0o755))
	writeFile(t, filepath.Join(dir, "ignored"), "App.java", "class App {}")
	writeFile(t, dir, "main.go", "package main")

	got, err := sources.HasSupportedSources(testIctx(t, nil), dir)

	require.NoError(t, err)
	assert.False(t, got, "supported file under an ignored path must not count")
}

func TestHasSupportedSources_RespectsTrackedFilesFlag(t *testing.T) {
	dir := gitRepoWithTrackedSource(t)
	writeFile(t, dir, ".gitignore", "ignored/\n")
	writeFile(t, filepath.Join(dir, "ignored"), "Untracked.java", "class Untracked {}")

	t.Run("disabled", func(t *testing.T) {
		got, err := sources.HasSupportedSources(testIctx(t, configuration.New()), dir)

		require.NoError(t, err)
		assert.False(t, got, "tracked files must retain legacy gitignore behavior when the flag is disabled")
	})

	t.Run("enabled", func(t *testing.T) {
		config := configuration.New()
		config.Set(utils.FF_GITIGNORE_RESPECT_TRACKED_FILES, true)

		got, err := sources.HasSupportedSources(testIctx(t, config), dir)

		require.NoError(t, err)
		assert.True(t, got, "a tracked supported file must survive gitignore filtering when the flag is enabled")
	})
}

func TestHasSupportedSources_NonexistentPath_ReturnsError(t *testing.T) {
	got, err := sources.HasSupportedSources(testIctx(t, nil), "/this/path/should/not/exist/ever")

	require.Error(t, err)
	assert.False(t, got)
}

func writeFile(t *testing.T, dir, name, body string) {
	t.Helper()
	p := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
}

func gitRepoWithTrackedSource(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "ignored"), 0o755))
	writeFile(t, filepath.Join(dir, "ignored"), "App.java", "class App {}")

	repository, err := git.PlainInit(dir, false)
	require.NoError(t, err)
	worktree, err := repository.Worktree()
	require.NoError(t, err)
	_, err = worktree.Add(filepath.ToSlash(filepath.Join("ignored", "App.java")))
	require.NoError(t, err)
	_, err = worktree.Commit("track source", &git.CommitOptions{
		Author: &object.Signature{
			Name:  "Test",
			Email: "test@snyk.io",
			When:  time.Now(),
		},
	})
	require.NoError(t, err)
	return dir
}
