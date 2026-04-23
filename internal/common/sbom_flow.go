package common

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	"github.com/snyk/cli-extension-os-flows/internal/constants"
	"github.com/snyk/cli-extension-os-flows/internal/legacy/definitions"
	"github.com/snyk/cli-extension-os-flows/internal/reachability"
	"github.com/snyk/cli-extension-os-flows/pkg/flags"
)

// RunSbomFlow uploads an SBOM document, resolves SCM context, optionally uploads
// source code for reachability, and runs a test via the test API.
// publishReport controls whether the test result is persisted as a monitored project;
// pass util.Ptr(true) for monitor, nil for test.
// runTest is the function used to execute the actual test against the test API.
func RunSbomFlow(
	ctx context.Context,
	sbomPath string,
	clients FlowClients,
	orgUUID uuid.UUID,
	localPolicy *testapi.LocalPolicy,
	reachabilityOpts *ReachabilityOpts,
	publishReport *bool,
	runTest RunTestWithResourcesFunc,
) ([]definitions.LegacyVulnerabilityResponse, []workflow.Data, error) {
	ictx := cmdctx.Ictx(ctx)
	cfg := cmdctx.Config(ctx)
	logger := cmdctx.Logger(ctx)
	progressBar := cmdctx.ProgressBar(ctx)
	inst := cmdctx.Instrumentation(ctx)

	progressBar.SetTitle("Uploading SBOM document...")
	fileChan := make(chan string, 1)
	fileChan <- sbomPath
	close(fileChan)

	sbomResult, err := clients.FileUploadClient.CreateRevisionFromChan(ctx, fileChan, filepath.Dir(sbomPath))
	if err != nil {
		logger.Error().Err(err).Str("sbomPath", sbomPath).Msg("Failed to upload SBOM")
		return nil, nil, fmt.Errorf("failed to upload SBOM: %w", err)
	}
	logger.Debug().Str("sbomRevisionID", sbomResult.RevisionID.String()).Msg("SBOM uploaded successfully")

	targetDir := filepath.Dir(sbomPath)
	scmInfo := ResolveScmInfo(targetDir, cfg.GetString(flags.FlagRemoteRepoURL), logger)

	var scmCtx *testapi.ScmContext
	if scmInfo != nil {
		scmCtx = &testapi.ScmContext{
			RepoUrl: &scmInfo.RemoteURL,
			Branch:  &scmInfo.Branch,
		}
	}

	sbomResource, err := NewUploadResource(sbomResult.RevisionID.String(), testapi.UploadResourceContentTypeSbom, scmCtx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create SBOM resource: %w", err)
	}

	resources := []testapi.TestResourceCreateItem{sbomResource}

	if reachabilityOpts != nil {
		progressBar.SetTitle(constants.UploadingSourceCodeMessage)

		var sourceResource testapi.TestResourceCreateItem
		sourceResource, err = UploadSourceCodeResource(ctx, orgUUID, clients.FileUploadClient, clients.DeeproxyClient, reachabilityOpts.SourceDir)
		if err != nil {
			logger.Warn().Err(err).Msg("Failed to upload source code, proceeding without reachability")
			//nolint:errcheck // Best-effort warning output.
			ictx.GetUserInterface().OutputError(reachability.NewWarning(err))
		} else {
			resources = append(resources, sourceResource)
		}
	}

	testConfig := BuildTestConfig(cfg, localPolicy, publishReport)

	osAnalysisStart := time.Now()
	legacyVuln, wfData, err := runTest(
		ctx, targetDir, clients.TestClient, resources,
		"", "", 0, sbomPath, sbomPath, orgUUID.String(), testConfig,
	)
	if inst != nil {
		inst.RecordOSAnalysisTime(time.Since(osAnalysisStart).Milliseconds())
	}

	var legacyVulnRes []definitions.LegacyVulnerabilityResponse
	if legacyVuln != nil {
		legacyVulnRes = []definitions.LegacyVulnerabilityResponse{*legacyVuln}
	}

	return legacyVulnRes, wfData, err
}
