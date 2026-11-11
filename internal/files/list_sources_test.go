package listsources_test

import (
	"fmt"
	"io"
	"path/filepath"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	gafmocks "github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	listsources "github.com/snyk/cli-extension-os-flows/internal/files"
	"github.com/snyk/cli-extension-os-flows/internal/util"
)

func Test_ListsSources_Simplest(t *testing.T) {
	sourcesDir := filepath.Join("testdata", "simplest")

	files, err := listSourcesForPath(t, sourcesDir)
	require.NoError(t, err)
	assert.Len(t, files, 2, "Expecting 2 files")
	assert.Contains(t, files, filepath.Join(sourcesDir, "package.json"))
	assert.Contains(t, files, filepath.Join(sourcesDir, "src", "index.js"))
}

func Test_ListsSources_WithIgnores(t *testing.T) {
	sourcesDir := filepath.Join("testdata", "with-ignores")

	files, err := listSourcesForPath(t, sourcesDir)
	require.NoError(t, err)

	assert.Len(t, files, 3, "Expecting 3 files")
	assert.Contains(t, files, filepath.Join(sourcesDir, ".gitignore"))
	assert.Contains(t, files, filepath.Join(sourcesDir, "package.json"))
	assert.Contains(t, files, filepath.Join(sourcesDir, "src", "with-ignores.js"))
}

func Test_PolicyFilesForPath_FindsNestedPolicyFilesAndHonoursIgnoreRules(t *testing.T) {
	dir := util.CreateTmpFiles(t, []util.LoadedFile{
		{Path: ".gitignore", Content: "ignored/\n"},
		{Path: ".snyk", Content: "version: v1.25.0\n"},
		{Path: "app/.snyk", Content: "version: v1.25.0\n"},
		{Path: "app/index.js"},
		{Path: "ignored/.snyk", Content: "version: v1.25.0\n"},
	}).Name()

	files, err := listsources.PolicyFilesForPath(fileFilterIctx(t), dir, 2)
	require.NoError(t, err)

	assert.ElementsMatch(t, []string{
		filepath.Join(dir, ".snyk"),
		filepath.Join(dir, "app", ".snyk"),
	}, files)
}

func listSourcesForPath(t *testing.T, sourcesDir string) ([]string, error) {
	t.Helper()
	filesCh, err := listsources.ForPath(fileFilterIctx(t), sourcesDir, 2)
	if err != nil {
		return nil, fmt.Errorf("failed to list sources: %w", err)
	}

	files := []string{}
	for file := range filesCh {
		files = append(files, file)
	}

	return files, nil
}

func fileFilterIctx(t *testing.T) *gafmocks.MockInvocationContext {
	t.Helper()
	logger := zerolog.New(io.Discard)
	config := configuration.New()
	ictx := gafmocks.NewMockInvocationContext(gomock.NewController(t))
	ictx.EXPECT().GetFileFilter(gomock.Any(), gomock.Any()).DoAndReturn(
		func(path string, options ...utils.FileFilterOption) *utils.FileFilter {
			return utils.NewFileFilter(path, &logger, append([]utils.FileFilterOption{utils.WithConfig(config)}, options...)...)
		},
	).AnyTimes()
	return ictx
}
