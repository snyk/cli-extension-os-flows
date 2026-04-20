package ostest

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	"github.com/snyk/cli-extension-os-flows/internal/common"
	"github.com/snyk/cli-extension-os-flows/internal/constants"
	"github.com/snyk/cli-extension-os-flows/internal/legacy/definitions"
)

// RunSbomFlow runs the SBOM flow with optional reachability analysis.
func RunSbomFlow(
	ctx context.Context,
	clients common.FlowClients,
	sbomPath string,
	orgUUID uuid.UUID,
	localPolicy *testapi.LocalPolicy,
	reachabilityOpts *common.ReachabilityOpts,
) ([]definitions.LegacyVulnerabilityResponse, []workflow.Data, error) {
	logger := cmdctx.Logger(ctx)
	progressBar := cmdctx.ProgressBar(ctx)
	instrumentation := cmdctx.Instrumentation(ctx)

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

	sbomResource, err := common.NewUploadResource(sbomResult.RevisionID.String(), testapi.UploadResourceContentTypeSbom, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create SBOM resource: %w", err)
	}

	resources := []testapi.TestResourceCreateItem{sbomResource}

	if reachabilityOpts != nil {
		progressBar.SetTitle(constants.UploadingSourceCodeMessage)

		var sourceResource testapi.TestResourceCreateItem
		sourceResource, err = common.UploadSourceCodeResource(ctx, orgUUID, clients.FileUploadClient, clients.DeeproxyClient, reachabilityOpts.SourceDir)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to upload source code: %w", err)
		}
		resources = append(resources, sourceResource)
	}

	targetDir := filepath.Dir(sbomPath)
	osAnalysisStart := time.Now()

	testConfig := &testapi.TestConfiguration{
		LocalPolicy: localPolicy,
		ScanConfig: &testapi.ScanConfiguration{
			Sca: &testapi.ScaScanConfiguration{},
		},
	}

	findings, summary, err := RunTestWithResources(
		ctx,
		targetDir,
		clients.TestClient,
		resources,
		"",
		"",
		0,
		sbomPath,
		sbomPath,
		orgUUID.String(),
		testConfig,
	)
	if err != nil {
		return nil, nil, err
	}
	if instrumentation != nil {
		instrumentation.RecordOSAnalysisTime(time.Since(osAnalysisStart).Milliseconds())
	}

	var allLegacyFindings []definitions.LegacyVulnerabilityResponse
	if findings != nil {
		allLegacyFindings = append(allLegacyFindings, *findings)
	}

	return allLegacyFindings, summary, nil
}
