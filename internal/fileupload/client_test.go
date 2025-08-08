//go:generate go run github.com/golang/mock/mockgen -package=mocks -destination=./mocks/mock_http_client.go github.com/snyk/cli-extension-os-flows/internal/fileupload/lowlevel SealableClient
package fileupload

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/fileupload/lowlevel"
)

func Test_UploadRevision(t *testing.T) {
	ctx := context.Background()
	fakeSealeableClient := lowlevel.NewFakeSealableClient(lowlevel.FakeClientConfig{
		Limits: lowlevel.Limits{
			FileCountLimit: 2,
			FileSizeLimit:  100,
		},
	})
	orgID := uuid.New()
	client := NewClient(Config{
		OrgID: orgID,
	}, WithLowLevelClient(fakeSealeableClient))

	t.Run("uploading a shallow directory", func(t *testing.T) {
		expectedFiles := []lowlevel.LoadedFile{
			{
				Path:    "file1",
				Content: "content1",
			},
			{
				Path:    "file2",
				Content: "content2",
			},
		}
		dir, cleanup := createDirWithFiles(expectedFiles)
		defer cleanup()

		revID, err := client.UploadDir(ctx, dir)

		require.NoError(t, err)
		uploadedFiles, err := fakeSealeableClient.GetSealedRevisionFiles(revID)
		require.NoError(t, err)
		expectEqualFiles(t, expectedFiles, uploadedFiles)
	})

	t.Run("uploading a directory with nested files", func(t *testing.T) {
		expectedFiles := []lowlevel.LoadedFile{
			{
				Path:    "src/main.go",
				Content: "package main\n\nfunc main() {}",
			},
			{
				Path:    "src/utils/helper.go",
				Content: "package utils\n\nfunc Helper() {}",
			},
		}
		dir, cleanup := createDirWithFiles(expectedFiles)
		defer cleanup()

		revID, err := client.UploadDir(ctx, dir)

		require.NoError(t, err)
		uploadedFiles, err := fakeSealeableClient.GetSealedRevisionFiles(revID)
		require.NoError(t, err)
		expectEqualFiles(t, expectedFiles, uploadedFiles)
	})

	t.Run("uploading a directory exceeding the file count limit for a single upload", func(t *testing.T) {
		expectedFiles := []lowlevel.LoadedFile{
			{
				Path:    "file1.txt",
				Content: "root level file",
			},
			{
				Path:    "src/main.go",
				Content: "package main\n\nfunc main() {}",
			},
			{
				Path:    "src/utils/helper.go",
				Content: "package utils\n\nfunc Helper() {}",
			},
			{
				Path:    "docs/README.md",
				Content: "# Project Documentation",
			},
		}
		dir, cleanup := createDirWithFiles(expectedFiles)
		defer cleanup()

		revID, err := client.UploadDir(ctx, dir)
		require.NoError(t, err)

		uploadedFiles, err := fakeSealeableClient.GetSealedRevisionFiles(revID)
		expectEqualFiles(t, expectedFiles, uploadedFiles)
	})
}

func expectEqualFiles(t *testing.T, expectedFiles, uploadedFiles []lowlevel.LoadedFile) {
	t.Helper()

	require.NotEmpty(t, uploadedFiles)
	require.Equal(t, len(expectedFiles), len(uploadedFiles))

	slices.SortFunc(expectedFiles, func(fileA, fileB lowlevel.LoadedFile) int {
		return strings.Compare(fileA.Path, fileB.Path)
	})

	slices.SortFunc(uploadedFiles, func(fileA, fileB lowlevel.LoadedFile) int {
		return strings.Compare(fileA.Path, fileB.Path)
	})

	for i := range uploadedFiles {
		assert.Equal(t, expectedFiles[i].Path, uploadedFiles[i].Path)
		assert.Equal(t, expectedFiles[i].Content, uploadedFiles[i].Content)
	}
}

func createDirWithFiles(files []lowlevel.LoadedFile) (dir *os.File, cleanup func()) {
	tempDir, err := os.MkdirTemp("", "cliuploadtest*")
	if err != nil {
		panic(err)
	}

	dir, err = os.Open(tempDir)
	if err != nil {
		panic(err)
	}

	for _, file := range files {
		fullPath := filepath.Join(tempDir, file.Path)

		parentDir := filepath.Dir(fullPath)
		if err := os.MkdirAll(parentDir, 0755); err != nil {
			panic(err)
		}

		f, err := os.Create(fullPath)
		if err != nil {
			panic(err)
		}

		defer f.Close()

		if _, err := f.WriteString(file.Content); err != nil {
			panic(err)
		}
	}

	cleanup = func() {
		if dir != nil {
			dir.Close()
		}
		if err := os.RemoveAll(tempDir); err != nil {
			fmt.Printf("failed to cleanup temp directory: %s\n", err.Error())
		}
	}

	return dir, cleanup
}
