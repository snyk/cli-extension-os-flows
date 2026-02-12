package reachability

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/snyk/go-application-framework/pkg/apiclients/fileupload"

	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	"github.com/snyk/cli-extension-os-flows/internal/deeproxy"
	listsources "github.com/snyk/cli-extension-os-flows/internal/files"
)

// CodeEngineProcessingLimit is the maximum file size (1MiB) that the code engine will process.
// Files larger than this are filtered out during source code upload.
const CodeEngineProcessingLimit = 1048576 // 1MiB

func codeEngineFilter(_ string, stat os.FileInfo) error {
	fileSize := stat.Size()
	if fileSize > CodeEngineProcessingLimit {
		return fmt.Errorf("files over 1MiB will not be processed by the code engine: file size (bytes): %d", fileSize)
	}
	return nil
}

func getDeeproxyFilter(ctx context.Context, orgID uuid.UUID, dclient deeproxy.Client) (fileFilter, error) {
	allowList, err := dclient.GetFilters(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to load file filters: %w", err)
	}

	supportedExtensions := make(map[string]bool)
	for _, ext := range allowList.Extensions {
		supportedExtensions[ext] = true
	}

	supportedConfigFiles := make(map[string]bool)
	for _, configFile := range allowList.ConfigFiles {
		// .gitignore and .dcignore should not be uploaded
		// (https://github.com/snyk/code-client/blob/d6f6a2ce4c14cb4b05aa03fb9f03533d8cf6ca4a/src/files.ts#L138)
		if configFile == ".gitignore" || configFile == ".dcignore" {
			continue
		}
		supportedConfigFiles[configFile] = true
	}

	return func(_ string, stat os.FileInfo) error {
		fileExt := filepath.Ext(stat.Name())
		fileName := filepath.Base(stat.Name())
		isSupportedExtension := supportedExtensions[fileExt]
		isSupportedConfigFile := supportedConfigFiles[fileName]

		if !isSupportedExtension && !isSupportedConfigFile {
			var reason error
			if !isSupportedConfigFile {
				reason = errors.Join(reason, fmt.Errorf("file name is not a part of the supported config files: %s", fileName))
			}
			if !isSupportedExtension {
				reason = errors.Join(reason, fmt.Errorf("file extension is not supported: %s", fileExt))
			}
			//nolint:wrapcheck // No need skipping causes.
			return reason
		}
		return nil
	}, nil
}

type fileFilter func(path string, stat os.FileInfo) error

func filterFiles(input <-chan string, output chan<- string, filteredFiles *[]fileupload.SkippedFile, filters ...fileFilter) {
	for path := range input {
		func() {
			f, err := os.Open(path)
			if err != nil {
				*filteredFiles = append(*filteredFiles, fileupload.SkippedFile{
					Path:   path,
					Reason: errors.New("failed to open file"),
				})
				return
			}

			defer f.Close()

			fstat, err := f.Stat()
			if err != nil {
				*filteredFiles = append(*filteredFiles, fileupload.SkippedFile{
					Path:   path,
					Reason: errors.New("failed to stat file"),
				})
				return
			}

			for _, filter := range filters {
				if err := filter(path, fstat); err != nil {
					*filteredFiles = append(*filteredFiles, fileupload.SkippedFile{
						Path:   path,
						Reason: err,
					})
					return
				}
			}

			output <- path
		}()
	}

	close(output)
}

// UploadSourceCode uploads a source code directory for reachability analysis.
// It applies the standard source code filters (1MiB file size limit).
func UploadSourceCode(
	ctx context.Context,
	orgID uuid.UUID,
	fc fileupload.Client,
	dclient deeproxy.Client,
	sourceDir string,
) (*fileupload.UploadResult, error) {
	instrumentation := cmdctx.Instrumentation(ctx)
	logger := cmdctx.Logger(ctx)
	codeUploadStart := time.Now()

	deeproxyFilter, err := getDeeproxyFilter(ctx, orgID, dclient)
	if err != nil {
		return nil, fmt.Errorf("failed to load deeproxy filter: %w", err)
	}

	inputFiles, err := listsources.ForPath(sourceDir, logger, runtime.NumCPU())
	if err != nil {
		return nil, fmt.Errorf("failed to list files in directory %s: %w", sourceDir, err)
	}

	filesToUpload := make(chan string)
	filteredFiles := make([]fileupload.SkippedFile, 0)
	go filterFiles(inputFiles,
		filesToUpload,
		&filteredFiles,
		codeEngineFilter,
		deeproxyFilter,
	)

	res, err := fc.CreateRevisionFromChan(ctx, filesToUpload, sourceDir)
	if err != nil {
		return nil, fmt.Errorf("failed to upload source code: %w", err)
	}

	if instrumentation != nil {
		instrumentation.RecordCodeUploadTime(time.Since(codeUploadStart).Milliseconds())
	}

	totalFileredFiles := slices.Concat(filteredFiles, res.SkippedFiles)
	for _, ff := range totalFileredFiles {
		logger.Debug().Str("file_path", ff.Path).Str("reason", ff.Reason.Error()).Msg("skipped file")
	}

	logger.Debug().
		Int("uploaded_files_count", res.UploadedFilesCount).
		Int("skipped_files_count", len(totalFileredFiles)).
		Msg("upload summary")

	return &res, nil
}

// GetReachabilityID will upload the source code directory using the file upload API,
// kick off a reachability scan, wait for the scan to complete and return the scan ID.
func GetReachabilityID(
	ctx context.Context,
	orgID uuid.UUID,
	sourceDir string,
	rc Client,
	fc fileupload.Client,
	dc deeproxy.Client,
) (ID, error) {
	instrumentation := cmdctx.Instrumentation(ctx)

	res, err := UploadSourceCode(ctx, orgID, fc, dc, sourceDir)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to upload source code for reachability analysis: %w", err)
	}

	codeAnalysisStart := time.Now()
	scanID, err := rc.StartReachabilityAnalysis(ctx, orgID, res.RevisionID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to start reachability analysis: %w", err)
	}

	err = rc.WaitForReachabilityAnalysis(ctx, orgID, scanID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed waiting for reachability analysis results: %w", err)
	}

	if instrumentation != nil {
		instrumentation.RecordCodeAnalysisTime(time.Since(codeAnalysisStart).Milliseconds())
	}

	return scanID, nil
}
