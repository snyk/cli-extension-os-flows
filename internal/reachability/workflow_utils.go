package reachability

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	"github.com/snyk/cli-extension-os-flows/internal/fileupload"
)

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
	res, err := fc.CreateRevisionFromDir(ctx, sourceDir, fileupload.UploadOptions{})
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
