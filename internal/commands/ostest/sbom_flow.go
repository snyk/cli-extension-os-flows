package ostest

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-os-flows/internal/bundlestore"
	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	"github.com/snyk/cli-extension-os-flows/internal/legacy/definitions"
	"github.com/snyk/cli-extension-os-flows/internal/presenters"
)

// RunSbomFlow runs the SBOM flow.
func RunSbomFlow(
	ctx context.Context,
	testClient testapi.TestClient,
	sbomPath string,
	sourceCodePath string,
	bsClient bundlestore.Client,
	orgID string,
	localPolicy *testapi.LocalPolicy,
	reachability bool,
) ([]definitions.LegacyVulnerabilityResponse, []workflow.Data, error) {
	logger := cmdctx.Logger(ctx)
	progressBar := cmdctx.ProgressBar(ctx)
	instrumentation := cmdctx.Instrumentation(ctx)
	ictx := cmdctx.Ictx(ctx)

	if ictx != nil {
		banner := presenters.RenderEarlyAccessBanner(presenters.SBOMEarlyAccessDocsURL)
		if err := ictx.GetUserInterface().Output(banner); err != nil {
			logger.Debug().Err(err).Msg("Failed to render Early Access banner")
		}
	}

	progressBar.SetTitle("Uploading SBOM document...")
	sbomBundleHash, err := bsClient.UploadSBOM(ctx, sbomPath)
	if err != nil {
		logger.Error().Err(err).Str("sbomPath", sbomPath).Msg("Failed to upload SBOM")
		return nil, nil, fmt.Errorf("failed to upload SBOM: %w", err)
	}
	logger.Println("sbomBundleHash", sbomBundleHash)

	var subject testapi.TestSubjectCreate
	if reachability {
		subject, err = createReachabilitySubject(ctx, bsClient, sbomPath, sourceCodePath, sbomBundleHash)
	} else {
		subject, err = createSbomSubject(ctx, sbomPath, sbomBundleHash)
	}

	if err != nil {
		return nil, nil, err
	}

	targetDir := filepath.Dir(sbomPath)
	osAnalysisStart := time.Now()
	findings, summary, err := RunTest(ctx, targetDir, testClient, subject, "", "", int(0), sbomPath, sbomPath, orgID, localPolicy)
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

func createReachabilitySubject(
	ctx context.Context,
	bsClient bundlestore.Client,
	sbomPath string,
	sourceCodePath string,
	sbomBundleHash string,
) (testapi.TestSubjectCreate, error) {
	logger := cmdctx.Logger(ctx)
	progressBar := cmdctx.ProgressBar(ctx)
	var subject testapi.TestSubjectCreate

	if validateErr := validateDirectory(ctx, sourceCodePath); validateErr != nil {
		return subject, validateErr
	}

	progressBar.SetTitle("Uploading source code...")
	sourceCodeBundleHash, uploadErr := bsClient.UploadSourceCode(ctx, sourceCodePath)
	if uploadErr != nil {
		//nolint:goconst // sourceCodePath is ok
		logger.Error().Err(uploadErr).Str("sourceCodePath", sourceCodePath).Msg("Failed to upload source code")
		return subject, fmt.Errorf("failed to upload source code: %w", uploadErr)
	}
	logger.Println("sourceCodeBundleHash", sourceCodeBundleHash)

	err := subject.FromSbomReachabilitySubject(testapi.SbomReachabilitySubject{
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
		return subject, fmt.Errorf("failed to create sbom test reachability subject: %w", err)
	}

	return subject, nil
}

func createSbomSubject(
	ctx context.Context,
	sbomPath string,
	sbomBundleHash string,
) (testapi.TestSubjectCreate, error) {
	logger := cmdctx.Logger(ctx)
	var subject testapi.TestSubjectCreate

	err := subject.FromSbomSubject(testapi.SbomSubject{
		Type:         testapi.SbomSubjectTypeSbom,
		SbomBundleId: sbomBundleHash,
		Locator: testapi.LocalPathLocator{
			Paths: []string{
				sbomPath,
			},
			Type: testapi.LocalPath,
		},
	})
	if err != nil {
		logger.Error().Err(err).Msg("Failed to create SBOM test subject")
		return subject, fmt.Errorf("failed to create sbom test subject: %w", err)
	}

	return subject, nil
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
