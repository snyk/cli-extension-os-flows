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

func listSourcesForPath(t *testing.T, sourcesDir string) ([]string, error) {
	t.Helper()
	mockLogger := zerolog.New(io.Discard)
	config := configuration.New()

	ictx := gafmocks.NewMockInvocationContext(gomock.NewController(t))
	ictx.EXPECT().GetFileFilter(gomock.Any(), gomock.Any()).DoAndReturn(
		func(path string, options ...utils.FileFilterOption) *utils.FileFilter {
			return utils.NewFileFilter(path, &mockLogger, append([]utils.FileFilterOption{utils.WithConfig(config)}, options...)...)
		}).AnyTimes()

	filesCh, err := listsources.ForPath(ictx, sourcesDir, 2)
	if err != nil {
		return nil, fmt.Errorf("failed to list sources: %w", err)
	}

	files := []string{}
	for file := range filesCh {
		files = append(files, file)
	}

	return files, nil
}
