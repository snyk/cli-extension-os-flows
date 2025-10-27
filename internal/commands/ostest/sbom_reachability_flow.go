package ostest

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-os-flows/internal/bundlestore"
	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	"github.com/snyk/cli-extension-os-flows/internal/legacy/definitions"
)

// RunSbomReachabilityFlow runs the SBOM reachability flow.
func RunSbomReachabilityFlow(
	ctx context.Context,
	testClient testapi.TestClient,
	sbomPath string,
	sourceCodePath string,
	bsClient bundlestore.Client,
	orgID string,
	localPolicy *testapi.LocalPolicy,
) ([]definitions.LegacyVulnerabilityResponse, []workflow.Data, error) {
	logger := cmdctx.Logger(ctx)
	progressBar := cmdctx.ProgressBar(ctx)

	if err := validateDirectory(ctx, sourceCodePath); err != nil {
		return nil, nil, err
	}

	progressBar.SetTitle("Uploading SBOM document...")
	sbomBundleHash, err := bsClient.UploadSBOM(ctx, sbomPath)
	if err != nil {
		logger.Error().Err(err).Str("sbomPath", sbomPath).Msg("Failed to upload SBOM")
		return nil, nil, fmt.Errorf("failed to upload SBOM: %w", err)
	}
	logger.Println("sbomBundleHash", sbomBundleHash)

	progressBar.SetTitle("Uploading source code...")
	sourceCodeBundleHash, err := bsClient.UploadSourceCode(ctx, sourceCodePath)
	if err != nil {
		//nolint:goconst // sourceCodePath is ok
		logger.Error().Err(err).Str("sourceCodePath", sourceCodePath).Msg("Failed to upload SBOM")
		return nil, nil, fmt.Errorf("failed to upload source code: %w", err)
	}
	logger.Println("sourceCodeBundleHash", sourceCodeBundleHash)

	var subject testapi.TestSubjectCreate
	err = subject.FromSbomReachabilitySubject(testapi.SbomReachabilitySubject{
		Type:         testapi.SbomReachability,
		CodeBundleId: sourceCodeBundleHash,
		SbomBundleId: sbomBundleHash,
		Locator: testapi.LocalPathLocator{
			Paths: []string{
				sbomPath,
				sourceCodePath,
			},
			Type: testapi.LocalPath,
		},
	})
	if err != nil {
		logger.Error().Err(err).Msg("Failed to create SBOM reachability test subject")
		return nil, nil, fmt.Errorf("failed to create sbom test reachability subject: %w", err)
	}

	targetDir := filepath.Dir(sbomPath)
	findings, summary, err := RunTest(ctx, targetDir, testClient, subject, "", "", int(0), sbomPath, orgID, localPolicy)
	if err != nil {
		return nil, nil, err
	}

	var allLegacyFindings []definitions.LegacyVulnerabilityResponse
	if findings != nil {
		allLegacyFindings = append(allLegacyFindings, *findings)
	}

	return allLegacyFindings, summary, nil
}

// validateDirectory checks if the given path exists and contains files.
func validateDirectory(ctx context.Context, sourceCodePath string) error {
	logger := cmdctx.Logger(ctx)
	errFactory := cmdctx.ErrorFactory(ctx)

	exists, err := dirExists(sourceCodePath)
	if err != nil {
		logger.Error().Err(err).Str("sourceCodePath", sourceCodePath).Msg("Failed to check if directory exists")
		return err
	}
	if !exists {
		return errFactory.NewDirectoryDoesNotExistError(sourceCodePath)
	}

	containsFiles, err := dirContainsFiles(sourceCodePath)
	if err != nil {
		logger.Error().Err(err).Str("sourceCodePath", sourceCodePath).Msg("Failed to read directory")
		return err
	}
	if !containsFiles {
		return errFactory.NewDirectoryIsEmptyError(sourceCodePath)
	}
	return nil
}

// dirExists checks if the given path exists as a directory.
func dirExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to check if directory exists: %w", err)
	}

	return true, nil
}

// dirContainsFiles checks if the given directory contains any files.
func dirContainsFiles(path string) (bool, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return false, fmt.Errorf("failed to read directory: %w", err)
	}

	return len(entries) > 0, nil
}
