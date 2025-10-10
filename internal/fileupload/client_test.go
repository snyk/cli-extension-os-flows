package fileupload_test

import (
	"context"
	"fmt"
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
	"github.com/snyk/cli-extension-os-flows/internal/util"
)

func Test_CreateRevisionFromPaths(t *testing.T) {
	llcfg := uploadrevision.FakeClientConfig{
		Limits: uploadrevision.Limits{
			FileCountLimit:        10,
			FileSizeLimit:         100,
			TotalPayloadSizeLimit: 10_000,
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

		ctx, fakeSealableClient, client, dir := setupTest(t, llcfg, allFiles, allowList, nil)

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

		ctx, _, client, dir := setupTest(t, llcfg, allFiles, filters.AllowList{}, assert.AnError)

		paths := []string{
			filepath.Join(dir.Name(), "src"),       // Directory
			filepath.Join(dir.Name(), "README.md"), // Individual file
		}

		_, err := client.CreateRevisionFromPaths(ctx, paths, fileupload.UploadOptions{})
		require.ErrorContains(t, err, "failed to load deeproxy filters")
	})

	t.Run("error handling with better context", func(t *testing.T) {
		ctx, _, client, _ := setupTest(t, llcfg, []uploadrevision.LoadedFile{}, allowList, nil)

		paths := []string{
			"/nonexistent/file.go",
			"/another/missing/path.txt",
		}

		_, err := client.CreateRevisionFromPaths(ctx, paths, fileupload.UploadOptions{})
		require.Error(t, err)
		var fileAccessErr *uploadrevision.FileAccessError
		assert.ErrorAs(t, err, &fileAccessErr)
		assert.Equal(t, "/nonexistent/file.go", fileAccessErr.FilePath)
		assert.ErrorContains(t, fileAccessErr.Err, "no such file or directory")
	})
}

func Test_CreateRevisionFromDir(t *testing.T) {
	llcfg := uploadrevision.FakeClientConfig{
		Limits: uploadrevision.Limits{
			FileCountLimit:        2,
			FileSizeLimit:         100,
			TotalPayloadSizeLimit: 10_000,
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
		ctx, fakeSealableClient, client, dir := setupTest(t, llcfg, expectedFiles, allowList, nil)

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
		ctx, fakeSealableClient, client, dir := setupTest(t, llcfg, expectedFiles, allowList, nil)

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
		ctx, fakeSealableClient, client, dir := setupTest(t, llcfg, expectedFiles, allowList, nil)

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
		ctx, fakeSealableClient, client, dir := setupTest(t, uploadrevision.FakeClientConfig{
			Limits: uploadrevision.Limits{
				FileCountLimit:        2,
				FileSizeLimit:         6,
				TotalPayloadSizeLimit: 100,
			},
		}, allFiles, allowList, nil)

		revID, err := client.CreateRevisionFromDir(ctx, dir.Name(), fileupload.UploadOptions{})
		require.NoError(t, err)

		uploadedFiles, err := fakeSealableClient.GetSealedRevisionFiles(revID)
		require.NoError(t, err)
		expectEqualFiles(t, expectedFiles, uploadedFiles)
	})

	t.Run("uploading a directory exceeding total payload size limit triggers batching", func(t *testing.T) {
		// Create files that together exceed the payload size limit but not the count limit
		// Each file is 30 bytes, limit is 70 bytes, so 3 files (90 bytes) should be split into 2 batches
		expectedFiles := []uploadrevision.LoadedFile{
			{
				Path:    "file1.txt",
				Content: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", // 30 bytes
			},
			{
				Path:    "file2.txt",
				Content: "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyy", // 30 bytes
			},
			{
				Path:    "file3.txt",
				Content: "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", // 30 bytes
			},
		}
		ctx, fakeSealableClient, client, dir := setupTest(t, uploadrevision.FakeClientConfig{
			Limits: uploadrevision.Limits{
				FileCountLimit:        10, // High enough to not trigger count-based batching
				FileSizeLimit:         50, // Each file is under this
				TotalPayloadSizeLimit: 70, // 70 bytes - forces batching by size
			},
		}, expectedFiles, allowList, nil)

		revID, err := client.CreateRevisionFromDir(ctx, dir.Name(), fileupload.UploadOptions{})
		require.NoError(t, err)

		// Success proves size-based batching works - without it, the low-level client
		// would reject the 90-byte payload (limit: 70 bytes).
		uploadedFiles, err := fakeSealableClient.GetSealedRevisionFiles(revID)
		require.NoError(t, err)
		expectEqualFiles(t, expectedFiles, uploadedFiles)
	})

	t.Run("uploading large individual files near payload limit", func(t *testing.T) {
		// Tests edge case where individual files are large relative to the payload limit.
		// File1: 150 bytes, File2: 80 bytes, File3: 60 bytes; Limit: 200 bytes
		// Expected batches: [File1], [File2], [File3] - each file in its own batch
		expectedFiles := []uploadrevision.LoadedFile{
			{
				Path:    "large1.txt",
				Content: string(make([]byte, 150)),
			},
			{
				Path:    "large2.txt",
				Content: string(make([]byte, 80)),
			},
			{
				Path:    "large3.txt",
				Content: string(make([]byte, 60)),
			},
		}
		ctx, fakeSealableClient, client, dir := setupTest(t, uploadrevision.FakeClientConfig{
			Limits: uploadrevision.Limits{
				FileCountLimit:        10,
				FileSizeLimit:         160,
				TotalPayloadSizeLimit: 200,
			},
		}, expectedFiles, allowList, nil)

		revID, err := client.CreateRevisionFromDir(ctx, dir.Name(), fileupload.UploadOptions{})
		require.NoError(t, err)

		uploadedFiles, err := fakeSealableClient.GetSealedRevisionFiles(revID)
		require.NoError(t, err)
		expectEqualFiles(t, expectedFiles, uploadedFiles)
	})

	t.Run("uploading files with variable sizes triggers optimal batching", func(t *testing.T) {
		// Tests realistic scenario with mixed file sizes.
		// Files: 10, 60, 5, 70, 45 bytes; Limit: 100 bytes
		// Expected batching: [10+60+5=75], [70], [45]
		expectedFiles := []uploadrevision.LoadedFile{
			{
				Path:    "tiny.txt",
				Content: string(make([]byte, 10)),
			},
			{
				Path:    "medium.txt",
				Content: string(make([]byte, 60)),
			},
			{
				Path:    "small.txt",
				Content: string(make([]byte, 5)),
			},
			{
				Path:    "large.txt",
				Content: string(make([]byte, 70)),
			},
			{
				Path:    "mid.txt",
				Content: string(make([]byte, 45)),
			},
		}
		ctx, fakeSealableClient, client, dir := setupTest(t, uploadrevision.FakeClientConfig{
			Limits: uploadrevision.Limits{
				FileCountLimit:        10,
				FileSizeLimit:         80,
				TotalPayloadSizeLimit: 100,
			},
		}, expectedFiles, allowList, nil)

		revID, err := client.CreateRevisionFromDir(ctx, dir.Name(), fileupload.UploadOptions{})
		require.NoError(t, err)

		uploadedFiles, err := fakeSealableClient.GetSealedRevisionFiles(revID)
		require.NoError(t, err)
		expectEqualFiles(t, expectedFiles, uploadedFiles)
	})

	t.Run("uploading directory where both size and count limits would be reached", func(t *testing.T) {
		// Tests scenario where both limits are approached.
		// 8 files of 30 bytes each = 240 bytes total
		// FileCountLimit: 10, TotalPayloadSizeLimit: 200 bytes
		// Should batch by size first: [file1-6=180], [file7-8=60]
		expectedFiles := make([]uploadrevision.LoadedFile, 8)
		for i := 0; i < 8; i++ {
			expectedFiles[i] = uploadrevision.LoadedFile{
				Path:    fmt.Sprintf("file%d.txt", i),
				Content: string(make([]byte, 30)),
			}
		}
		ctx, fakeSealableClient, client, dir := setupTest(t, uploadrevision.FakeClientConfig{
			Limits: uploadrevision.Limits{
				FileCountLimit:        10,
				FileSizeLimit:         50,
				TotalPayloadSizeLimit: 200,
			},
		}, expectedFiles, allowList, nil)

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

		ctx, fakeSealableClient, client, dir := setupTest(t, llcfg, allFiles, allowList, nil)

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

		ctx, fakeSealableClient, client, dir := setupTest(t, llcfg, allFiles, allowList, nil)

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
			FileCountLimit:        2,
			FileSizeLimit:         100,
			TotalPayloadSizeLimit: 10_000,
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
		ctx, fakeSealableClient, client, dir := setupTest(t, llcfg, expectedFiles, allowList, nil)

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
		ctx, _, client, dir := setupTest(t, uploadrevision.FakeClientConfig{
			Limits: uploadrevision.Limits{
				FileCountLimit:        1,
				FileSizeLimit:         6,
				TotalPayloadSizeLimit: 10_000,
			},
		}, expectedFiles, allowList, nil)

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

		ctx, fakeSealableClient, client, dir := setupTest(t, llcfg, allFiles, allowList, nil)

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

		ctx, fakeSealableClient, client, dir := setupTest(t, llcfg, expectedFiles, allowList, nil)

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

func setupTest(
	t *testing.T,
	llcfg uploadrevision.FakeClientConfig,
	files []uploadrevision.LoadedFile,
	allowList filters.AllowList,
	filtersErr error,
) (context.Context, *uploadrevision.FakeSealableClient, *fileupload.HTTPClient, *os.File) {
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

	dir := util.CreateTmpFiles(t, files)

	return ctx, fakeSealeableClient, client, dir
}
