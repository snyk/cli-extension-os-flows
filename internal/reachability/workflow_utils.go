package reachability

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	"github.com/snyk/cli-extension-os-flows/internal/fileupload"
)

// CodeEngineProcessingLimit is the maximum file size (1MiB) that the code engine will process.
// Files larger than this are filtered out during source code upload.
const CodeEngineProcessingLimit = 1048576 // 1MiB

// SourceCodeUploadOptions returns the upload options for source code uploads.
// This includes a filter to exclude files larger than the code engine processing limit.
func SourceCodeUploadOptions() fileupload.UploadOptions {
	return fileupload.UploadOptions{
		AdditionalFilters: []fileupload.Filter{
			func(ftf fileupload.FileToFilter) *fileupload.FilteredFile {
				fileSize := ftf.Stat.Size()
				if fileSize > CodeEngineProcessingLimit {
					return &fileupload.FilteredFile{
						Path:   ftf.Path,
						Reason: fmt.Errorf("files over 1MiB will not be processed by the code engine: file size (bytes): %d", fileSize),
					}
				}
				return nil
			},
		},
	}
}

// UploadSourceCode uploads a source code directory for reachability analysis.
// It applies the standard source code filters (1MiB file size limit).
func UploadSourceCode(
	ctx context.Context,
	fc fileupload.Client,
	sourceDir string,
) (fileupload.UploadResult, error) {
	instrumentation := cmdctx.Instrumentation(ctx)
	codeUploadStart := time.Now()

	res, err := fc.CreateRevisionFromDir(ctx, sourceDir, SourceCodeUploadOptions())
	if err != nil {
		return fileupload.UploadResult{}, fmt.Errorf("failed to upload source code: %w", err)
	}

	if instrumentation != nil {
		instrumentation.RecordCodeUploadTime(time.Since(codeUploadStart).Milliseconds())
	}

	return res, nil
}

// GetReachabilityID will upload the source code directory using the file upload API,
// kick off a reachability scan, wait for the scan to complete and return the scan ID.
func GetReachabilityID(
	ctx context.Context,
	orgID uuid.UUID,
	sourceDir string,
	rc Client,
	fc fileupload.Client,
) (ID, error) {
	instrumentation := cmdctx.Instrumentation(ctx)

	res, err := UploadSourceCode(ctx, fc, sourceDir)
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
