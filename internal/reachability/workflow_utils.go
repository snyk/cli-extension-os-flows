package reachability

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/snyk/cli-extension-os-flows/internal/bundlestore"
)

// GetReachabilityID will upload the source code directory, kick off a reachability scan, wait for the scan to complete and return the scan ID.
func GetReachabilityID(ctx context.Context, orgID uuid.UUID, sourceDir string, rc Client, bc bundlestore.Client) (ID, error) {
	if sourceDir == "" {
		sourceDir = "."
	}

	hash, err := bc.UploadSourceCode(ctx, sourceDir)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to upload source code: %w", err)
	}

	scanID, err := rc.StartReachabilityAnalysis(ctx, orgID, hash)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to start reachability analysis: %w", err)
	}

	err = rc.WaitForReachabilityAnalysis(ctx, orgID, scanID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed waiting for reachability analysis results: %w", err)
	}

	return scanID, nil
}
