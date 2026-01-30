package ostest

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	"github.com/snyk/cli-extension-os-flows/internal/fileupload"
	"github.com/snyk/cli-extension-os-flows/internal/legacy/definitions"
	"github.com/snyk/cli-extension-os-flows/internal/reachability"
)

// RunSbomFlow runs the SBOM flow with optional reachability analysis.
func RunSbomFlow(
	ctx context.Context,
	testClient testapi.TestClient,
	sbomPath string,
	sourceCodePath string,
	fuClient fileupload.Client,
	orgID string,
	localPolicy *testapi.LocalPolicy,
	reachability bool,
) ([]definitions.LegacyVulnerabilityResponse, []workflow.Data, error) {
	logger := cmdctx.Logger(ctx)
	progressBar := cmdctx.ProgressBar(ctx)
	instrumentation := cmdctx.Instrumentation(ctx)

	progressBar.SetTitle("Uploading SBOM document...")
	sbomResult, err := fuClient.CreateRevisionFromFile(ctx, sbomPath, fileupload.UploadOptions{
		SkipDeeproxyFiltering: true,
	})
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

	if reachability {
		var sourceResource testapi.TestResourceCreateItem
		sourceResource, err = uploadSourceCodeResource(ctx, fuClient, sourceCodePath)
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

	findings, summary, err := RunTestWithResources(ctx, targetDir, testClient, resources, "", "", 0, sbomPath, sbomPath, orgID, localPolicy, scanConfig)
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
	fuClient fileupload.Client,
	sourceCodePath string,
) (testapi.TestResourceCreateItem, error) {
	logger := cmdctx.Logger(ctx)
	progressBar := cmdctx.ProgressBar(ctx)

	progressBar.SetTitle("Uploading source code...")
	sourceResult, err := reachability.UploadSourceCode(ctx, fuClient, sourceCodePath)
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
