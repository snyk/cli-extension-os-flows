package fileupload_test

import (
	"context"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/fileupload"
	"github.com/snyk/cli-extension-os-flows/internal/fileupload/filters"
	"github.com/snyk/cli-extension-os-flows/internal/fileupload/uploadrevision"
)

func Test_CreateRevisionFromPaths(t *testing.T) {
	llcfg := uploadrevision.FakeClientConfig{
		Limits: uploadrevision.Limits{
			FileCountLimit: 10,
			FileSizeLimit:  100,
		},
	}

	allowList := filters.AllowList{
		ConfigFiles: []string{"go.mod"},
		Extensions:  []string{".txt", ".go", ".md"},
	}

	t.Run("mixed files and directories", func(t *testing.T) {
		allFiles := []uploadrevision.LoadedFile{
			{Path: "src/main.go", Content: "package main"},
			{Path: "src/utils.go", Content: "package utils"},
			{Path: "config.yaml", Content: "version: 1"},
			{Path: "README.md", Content: "# Project"},
		}

		ctx, fakeSealableClient, client, dir, cleanup := setupTest(t, llcfg, allFiles, allowList, nil)
		defer cleanup()

		paths := []string{
			filepath.Join(dir.Name(), "src"),       // Directory
			filepath.Join(dir.Name(), "README.md"), // Individual file
		}

		revID, err := client.CreateRevisionFromPaths(ctx, paths, fileupload.UploadOptions{})
		require.NoError(t, err)

		uploadedFiles, err := fakeSealableClient.GetSealedRevisionFiles(revID)
		require.NoError(t, err)
		require.Len(t, uploadedFiles, 3) // 2 from src/ + 1 README.md

		uploadedPaths := make([]string, len(uploadedFiles))
		for i, f := range uploadedFiles {
			uploadedPaths[i] = f.Path
		}
		assert.Contains(t, uploadedPaths, "main.go")
		assert.Contains(t, uploadedPaths, "utils.go")
		assert.Contains(t, uploadedPaths, "README.md")
	})

	t.Run("get filters error", func(t *testing.T) {
		allFiles := []uploadrevision.LoadedFile{
			{Path: "src/main.go", Content: "package main"},
			{Path: "src/utils.go", Content: "package utils"},
			{Path: "config.yaml", Content: "version: 1"},
			{Path: "README.md", Content: "# Project"},
		}

		ctx, _, client, dir, cleanup := setupTest(t, llcfg, allFiles, filters.AllowList{}, assert.AnError)
		defer cleanup()

		paths := []string{
			filepath.Join(dir.Name(), "src"),       // Directory
			filepath.Join(dir.Name(), "README.md"), // Individual file
		}

		_, err := client.CreateRevisionFromPaths(ctx, paths, fileupload.UploadOptions{})
		require.ErrorContains(t, err, "failed to load deeproxy filters")
	})

	t.Run("error handling with better context", func(t *testing.T) {
		ctx, _, client, _, cleanup := setupTest(t, llcfg, []uploadrevision.LoadedFile{}, allowList, nil)
		defer cleanup()

		paths := []string{
			"/nonexistent/file.go",
			"/another/missing/path.txt",
		}

		_, err := client.CreateRevisionFromPaths(ctx, paths, fileupload.UploadOptions{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to stat path")
		assert.Contains(t, err.Error(), "/nonexistent/file.go") // Should include the specific path
	})
}

func Test_CreateRevisionFromDir(t *testing.T) {
	llcfg := uploadrevision.FakeClientConfig{
		Limits: uploadrevision.Limits{
			FileCountLimit: 2,
			FileSizeLimit:  100,
		},
	}

	allowList := filters.AllowList{
		ConfigFiles: []string{"go.mod"},
		Extensions:  []string{".txt", ".go", ".md"},
	}

	t.Run("uploading a shallow directory", func(t *testing.T) {
		expectedFiles := []uploadrevision.LoadedFile{
			{
				Path:    "file1.txt",
				Content: "content1",
			},
			{
				Path:    "file2.txt",
				Content: "content2",
			},
		}
		ctx, fakeSealableClient, client, dir, cleanup := setupTest(t, llcfg, expectedFiles, allowList, nil)
		defer cleanup()

		revID, err := client.CreateRevisionFromDir(ctx, dir.Name(), fileupload.UploadOptions{})

		require.NoError(t, err)
		uploadedFiles, err := fakeSealableClient.GetSealedRevisionFiles(revID)
		require.NoError(t, err)
		expectEqualFiles(t, expectedFiles, uploadedFiles)
	})

	t.Run("uploading a directory with nested files", func(t *testing.T) {
		expectedFiles := []uploadrevision.LoadedFile{
			{
				Path:    "src/main.go",
				Content: "package main\n\nfunc main() {}",
			},
			{
				Path:    "src/utils/helper.go",
				Content: "package utils\n\nfunc Helper() {}",
			},
		}
		ctx, fakeSealableClient, client, dir, cleanup := setupTest(t, llcfg, expectedFiles, allowList, nil)
		defer cleanup()

		revID, err := client.CreateRevisionFromDir(ctx, dir.Name(), fileupload.UploadOptions{})

		require.NoError(t, err)
		uploadedFiles, err := fakeSealableClient.GetSealedRevisionFiles(revID)
		require.NoError(t, err)
		expectEqualFiles(t, expectedFiles, uploadedFiles)
	})

	t.Run("uploading a directory exceeding the file count limit for a single upload", func(t *testing.T) {
		expectedFiles := []uploadrevision.LoadedFile{
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
			{
				Path:    "src/go.mod",
				Content: "foo bar",
			},
		}
		ctx, fakeSealableClient, client, dir, cleanup := setupTest(t, llcfg, expectedFiles, allowList, nil)
		defer cleanup()

		revID, err := client.CreateRevisionFromDir(ctx, dir.Name(), fileupload.UploadOptions{})
		require.NoError(t, err)

		uploadedFiles, err := fakeSealableClient.GetSealedRevisionFiles(revID)
		require.NoError(t, err)
		expectEqualFiles(t, expectedFiles, uploadedFiles)
	})

	t.Run("uploading a directory with file exceeding the file size limit", func(t *testing.T) {
		expectedFiles := []uploadrevision.LoadedFile{
			{
				Path:    "file2.txt",
				Content: "foo",
			},
		}
		additionalFiles := []uploadrevision.LoadedFile{
			{
				Path:    "file1.txt",
				Content: "foo bar",
			},
		}

		allFiles := make([]uploadrevision.LoadedFile, 0, 2)
		allFiles = append(allFiles, expectedFiles...)
		allFiles = append(allFiles, additionalFiles...)
		ctx, fakeSealableClient, client, dir, cleanup := setupTest(t, uploadrevision.FakeClientConfig{
			Limits: uploadrevision.Limits{
				FileCountLimit: 2,
				FileSizeLimit:  6,
			},
		}, allFiles, allowList, nil)
		defer cleanup()

		revID, err := client.CreateRevisionFromDir(ctx, dir.Name(), fileupload.UploadOptions{})
		require.NoError(t, err)

		uploadedFiles, err := fakeSealableClient.GetSealedRevisionFiles(revID)
		require.NoError(t, err)
		expectEqualFiles(t, expectedFiles, uploadedFiles)
	})

	t.Run("uploading a directory applies filtering", func(t *testing.T) {
		expectedFiles := []uploadrevision.LoadedFile{
			{
				Path:    "src/main.go",
				Content: "package main\n\nfunc main() {}",
			},
			{
				Path:    "src/utils/helper.go",
				Content: "package utils\n\nfunc Helper() {}",
			},
			{
				Path:    "src/go.mod",
				Content: "foo bar",
			},
		}
		additionalFiles := []uploadrevision.LoadedFile{
			{
				Path:    "src/script.js",
				Content: "console.log('hi')",
			},
			{
				Path:    "src/package.json",
				Content: "{}",
			},
		}
		//nolint:gocritic // Not an issue for tests.
		allFiles := append(expectedFiles, additionalFiles...)

		ctx, fakeSealableClient, client, dir, cleanup := setupTest(t, llcfg, allFiles, allowList, nil)
		defer cleanup()

		revID, err := client.CreateRevisionFromDir(ctx, dir.Name(), fileupload.UploadOptions{})
		require.NoError(t, err)

		uploadedFiles, err := fakeSealableClient.GetSealedRevisionFiles(revID)
		require.NoError(t, err)
		expectEqualFiles(t, expectedFiles, uploadedFiles)
	})

	t.Run("uploading a directory with filtering disabled", func(t *testing.T) {
		allFiles := []uploadrevision.LoadedFile{
			{
				Path:    "src/main.go",
				Content: "package main\n\nfunc main() {}",
			},
			{
				Path:    "src/utils/helper.go",
				Content: "package utils\n\nfunc Helper() {}",
			},
			{
				Path:    "src/go.mod",
				Content: "foo bar",
			},
			{
				Path:    "src/script.js",
				Content: "console.log('hi')",
			},
			{
				Path:    "src/package.json",
				Content: "{}",
			},
		}

		ctx, fakeSealableClient, client, dir, cleanup := setupTest(t, llcfg, allFiles, allowList, nil)
		defer cleanup()

		revID, err := client.CreateRevisionFromDir(ctx, dir.Name(), fileupload.UploadOptions{SkipFiltering: true})
		require.NoError(t, err)

		uploadedFiles, err := fakeSealableClient.GetSealedRevisionFiles(revID)
		require.NoError(t, err)
		expectEqualFiles(t, allFiles, uploadedFiles)
	})
}

func Test_CreateRevisionFromFile(t *testing.T) {
	llcfg := uploadrevision.FakeClientConfig{
		Limits: uploadrevision.Limits{
			FileCountLimit: 2,
			FileSizeLimit:  100,
		},
	}

	allowList := filters.AllowList{
		ConfigFiles: []string{"go.mod"},
		Extensions:  []string{".txt", ".go", ".md"},
	}

	t.Run("uploading a file", func(t *testing.T) {
		expectedFiles := []uploadrevision.LoadedFile{
			{
				Path:    "file1.txt",
				Content: "content1",
			},
		}
		ctx, fakeSealableClient, client, dir, cleanup := setupTest(t, llcfg, expectedFiles, allowList, nil)
		defer cleanup()

		revID, err := client.CreateRevisionFromFile(ctx, path.Join(dir.Name(), "file1.txt"), fileupload.UploadOptions{})

		require.NoError(t, err)
		uploadedFiles, err := fakeSealableClient.GetSealedRevisionFiles(revID)
		require.NoError(t, err)
		expectEqualFiles(t, expectedFiles, uploadedFiles)
	})

	t.Run("uploading a file exceeding the file size limit", func(t *testing.T) {
		expectedFiles := []uploadrevision.LoadedFile{
			{
				Path:    "file1.txt",
				Content: "foo bar",
			},
		}
		ctx, _, client, dir, cleanup := setupTest(t, uploadrevision.FakeClientConfig{
			Limits: uploadrevision.Limits{
				FileCountLimit: 1,
				FileSizeLimit:  6,
			},
		}, expectedFiles, allowList, nil)
		defer cleanup()

		_, err := client.CreateRevisionFromFile(ctx, path.Join(dir.Name(), "file1.txt"), fileupload.UploadOptions{})

		require.ErrorIs(t, err, uploadrevision.ErrNoFilesProvided)
	})

	t.Run("uploading a file applies filtering", func(t *testing.T) {
		allFiles := []uploadrevision.LoadedFile{
			{
				Path:    "script.js",
				Content: "console.log('hi')",
			},
		}

		ctx, fakeSealableClient, client, dir, cleanup := setupTest(t, llcfg, allFiles, allowList, nil)
		defer cleanup()

		revID, err := client.CreateRevisionFromFile(ctx, path.Join(dir.Name(), "script.js"), fileupload.UploadOptions{})
		require.NoError(t, err)

		uploadedFiles, err := fakeSealableClient.GetSealedRevisionFiles(revID)
		require.NoError(t, err)
		expectEqualFiles(t, nil, uploadedFiles)
	})

	t.Run("uploading a file with filtering disabled", func(t *testing.T) {
		expectedFiles := []uploadrevision.LoadedFile{
			{
				Path:    "script.js",
				Content: "console.log('hi')",
			},
		}

		ctx, fakeSealableClient, client, dir, cleanup := setupTest(t, llcfg, expectedFiles, allowList, nil)
		defer cleanup()

		revID, err := client.CreateRevisionFromFile(ctx, path.Join(dir.Name(), "script.js"), fileupload.UploadOptions{SkipFiltering: true})
		require.NoError(t, err)

		uploadedFiles, err := fakeSealableClient.GetSealedRevisionFiles(revID)
		require.NoError(t, err)
		expectEqualFiles(t, expectedFiles, uploadedFiles)
	})
}

func expectEqualFiles(t *testing.T, expectedFiles, uploadedFiles []uploadrevision.LoadedFile) {
	t.Helper()

	require.Equal(t, len(expectedFiles), len(uploadedFiles))

	slices.SortFunc(expectedFiles, func(fileA, fileB uploadrevision.LoadedFile) int {
		return strings.Compare(fileA.Path, fileB.Path)
	})

	slices.SortFunc(uploadedFiles, func(fileA, fileB uploadrevision.LoadedFile) int {
		return strings.Compare(fileA.Path, fileB.Path)
	})

	for i := range uploadedFiles {
		assert.Equal(t, expectedFiles[i].Path, uploadedFiles[i].Path)
		assert.Equal(t, expectedFiles[i].Content, uploadedFiles[i].Content)
	}
}

func createDirWithFiles(t *testing.T, files []uploadrevision.LoadedFile) (dir *os.File, cleanup func()) {
	t.Helper()

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

	cleanup = func() {
		if dir != nil {
			dir.Close()
		}
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("failed to cleanup temp directory: %s\n", err.Error())
		}
	}

	return dir, cleanup
}

func setupTest(
	t *testing.T,
	llcfg uploadrevision.FakeClientConfig,
	files []uploadrevision.LoadedFile,
	allowList filters.AllowList,
	filtersErr error,
) (context.Context, *uploadrevision.FakeSealableClient, *fileupload.HTTPClient, *os.File, func()) {
	t.Helper()

	ctx := context.Background()
	orgID := uuid.New()

	fakeSealeableClient := uploadrevision.NewFakeSealableClient(llcfg)
	fakeFiltersClient := filters.NewFakeClient(allowList, filtersErr)
	client := fileupload.NewClient(
		nil,
		fileupload.Config{
			OrgID: orgID,
		},
		fileupload.WithUploadRevisionSealableClient(fakeSealeableClient),
		fileupload.WithFiltersClient(fakeFiltersClient),
	)

	dir, dirCleanup := createDirWithFiles(t, files)

	return ctx, fakeSealeableClient, client, dir, func() {
		dirCleanup()
	}
}
