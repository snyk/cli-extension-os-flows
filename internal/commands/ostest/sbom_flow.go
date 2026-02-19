package ostest

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/snyk/go-application-framework/pkg/apiclients/fileupload"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	"github.com/snyk/cli-extension-os-flows/internal/deeproxy"
	"github.com/snyk/cli-extension-os-flows/internal/legacy/definitions"
	"github.com/snyk/cli-extension-os-flows/internal/reachability"
)

// RunSbomFlow runs the SBOM flow with optional reachability analysis.
func RunSbomFlow(
	ctx context.Context,
	clients FlowClients,
	sbomPath string,
	orgUUID uuid.UUID,
	localPolicy *testapi.LocalPolicy,
	reachabilityOpts *ReachabilityOpts,
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

	sbomResource, err := newUploadResource(sbomResult.RevisionID.String(), testapi.UploadResourceContentTypeSbom)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create SBOM resource: %w", err)
	}

	resources := []testapi.TestResourceCreateItem{sbomResource}

	if reachabilityOpts != nil {
		progressBar.SetTitle("Uploading source code...")

		var sourceResource testapi.TestResourceCreateItem
		sourceResource, err = uploadSourceCodeResource(ctx, orgUUID, clients.FileUploadClient, clients.DeeproxyClient, reachabilityOpts.SourceDir)
		if err != nil {
			return nil, nil, err
		}
		resources = append(resources, sourceResource)
	}

	targetDir := filepath.Dir(sbomPath)
	osAnalysisStart := time.Now()

	scanConfig := &testapi.ScanConfiguration{
		Sca: &testapi.ScaScanConfiguration{},
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
		localPolicy,
		scanConfig,
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

// uploadSourceCodeResource uploads source code and creates the test resource.
func uploadSourceCodeResource(
	ctx context.Context,
	orgID uuid.UUID,
	fc fileupload.Client,
	dc deeproxy.Client,
	sourceCodePath string,
) (testapi.TestResourceCreateItem, error) {
	logger := cmdctx.Logger(ctx)

	sourceResult, err := reachability.UploadSourceCode(ctx, orgID, fc, dc, sourceCodePath)
	if err != nil {
		logger.Error().Err(err).Str("sourceCodePath", sourceCodePath).Msg("Failed to upload source code")
		return testapi.TestResourceCreateItem{}, fmt.Errorf("failed to upload source code: %w", err)
	}
	logger.Debug().Str("sourceRevisionID", sourceResult.RevisionID.String()).Msg("Source code uploaded successfully")

	return newUploadResource(sourceResult.RevisionID.String(), testapi.UploadResourceContentTypeSource)
}

// newUploadResource creates a TestResourceCreateItem from a revision ID and content type.
func newUploadResource(revisionID string, contentType testapi.UploadResourceContentType) (testapi.TestResourceCreateItem, error) {
	uploadResource := testapi.UploadResource{
		ContentType:  contentType,
		FilePatterns: []string{},
		RevisionId:   revisionID,
		Type:         testapi.Upload,
	}

	var resourceVariant testapi.BaseResourceVariantCreateItem
	if err := resourceVariant.FromUploadResource(uploadResource); err != nil {
		return testapi.TestResourceCreateItem{}, fmt.Errorf("failed to create resource variant: %w", err)
	}

	baseResource := testapi.BaseResourceCreateItem{
		Resource: resourceVariant,
		Type:     testapi.BaseResourceCreateItemTypeBase,
	}

	var testResource testapi.TestResourceCreateItem
	if err := testResource.FromBaseResourceCreateItem(baseResource); err != nil {
		return testapi.TestResourceCreateItem{}, fmt.Errorf("failed to create test resource: %w", err)
	}

	return testResource, nil
}
