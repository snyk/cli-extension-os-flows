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
	"github.com/snyk/cli-extension-os-flows/internal/legacy/definitions"
	"github.com/snyk/cli-extension-os-flows/pkg/flags"
)

// RunSbomFlow uploads an SBOM document, resolves SCM context, optionally uploads
// source code for reachability, and runs a test via the test API.
// runTest is the function used to execute the actual test against the test API.
func RunSbomFlow(
	ctx context.Context,
	sbomPath string,
	clients FlowClients,
	orgUUID uuid.UUID,
	localPolicy *testapi.LocalPolicy,
	reachabilityOpts *ReachabilityOpts,
	runTest RunTestWithResourcesByComponentFunc,
) ([]definitions.LegacyVulnerabilityResponse, []workflow.Data, error) {
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
		if upload := uploadReachabilitySourcesIfAny(ctx, orgUUID, clients, reachabilityOpts); upload != nil {
			resources = append(resources, *upload)
		}
	}

	testConfig := BuildTestConfig(cfg, localPolicy)

	osAnalysisStart := time.Now()
	// The SBOM is tested as a single test, but it may cover several components. The results
	// are reported one per component, matching how `snyk test --all-projects` reports one
	// result per project.
	legacyVulnRes, wfData, err := runTest(
		ctx, targetDir, clients.TestClient, resources,
		"", "", 0, sbomPath, sbomPath, orgUUID.String(), testConfig,
	)
	if inst != nil {
		inst.RecordOSAnalysisTime(time.Since(osAnalysisStart).Milliseconds())
	}

	return legacyVulnRes, wfData, err
}
