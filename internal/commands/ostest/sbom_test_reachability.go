package ostest

import (
	"context"
	"fmt"
	"os"

	"github.com/rs/zerolog"

	"github.com/snyk/cli-extension-os-flows/internal/bundlestore"
	"github.com/snyk/cli-extension-os-flows/internal/errors"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// BundlestoreClient is exported to allow it to be mocked.
var BundlestoreClient bundlestore.Client

func sbomTestReachability(
	ctx context.Context,
	config configuration.Configuration,
	errFactory *errors.ErrorFactory,
	ictx workflow.InvocationContext,
	logger *zerolog.Logger,
	sbomPath string,
	sourceCodePath string,
) ([]workflow.Data, error) {
	if sourceCodePath == "" {
		sourceCodePath = "."
	}

	if err := validateDirectory(sourceCodePath, logger, errFactory); err != nil {
		return nil, err
	}

	if BundlestoreClient == nil {
		BundlestoreClient = bundlestore.NewClient(config, ictx.GetNetworkAccess().GetHttpClient, logger)
	}

	sbomBundleHash, err := BundlestoreClient.UploadSBOM(ctx, sbomPath)
	if err != nil {
		logger.Error().Err(err).Str("sbomPath", sbomPath).Msg("Failed to upload SBOM")
		return nil, fmt.Errorf("failed to upload SBOM: %w", err)
	}
	logger.Println("sbomBundleHash", sbomBundleHash)

	sourceCodeBundleHash, err := BundlestoreClient.UploadSourceCode(ctx, sourceCodePath)
	if err != nil {
		//nolint:goconst // sourceCodePath is ok
		logger.Error().Err(err).Str("sourceCodePath", sourceCodePath).Msg("Failed to upload SBOM")
		return nil, fmt.Errorf("failed to upload source code: %w", err)
	}
	logger.Println("sourceCodeBundleHash", sourceCodeBundleHash)

	return nil, nil // TODO: return something meaningful once this function is complete
}

func validateDirectory(sourceCodePath string, logger *zerolog.Logger, errFactory *errors.ErrorFactory) error {
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

func dirContainsFiles(path string) (bool, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return false, fmt.Errorf("failed to read directory: %w", err)
	}

	return len(entries) > 0, nil
}
