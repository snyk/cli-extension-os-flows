package reachability

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	"github.com/snyk/cli-extension-os-flows/internal/fileupload"
)

const codeEngineProcessingLimit = 1048567 // 1MiB

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
	codeUploadStart := time.Now()
	res, err := fc.CreateRevisionFromDir(ctx, sourceDir, fileupload.UploadOptions{
		AdditionalFilters: []fileupload.Filter{
			func(ftf fileupload.FileToFilter) *fileupload.FilteredFile {
				fileSize := ftf.Stat.Size()
				if fileSize > codeEngineProcessingLimit { // 1MiB
					return &fileupload.FilteredFile{
						Path:   ftf.Path,
						Reason: fmt.Errorf("files over 1MiB will not be processed by the code engine: file size (bytes): %d", fileSize),
					}
				}

				return nil
			},
		},
	})
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to upload source code for reachability analysis: %w", err)
	}

	if instrumentation != nil {
		instrumentation.RecordCodeUploadTime(time.Since(codeUploadStart).Milliseconds())
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
