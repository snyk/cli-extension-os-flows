package common

import (
	"context"
	"os"

	"github.com/google/uuid"

	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	"github.com/snyk/cli-extension-os-flows/internal/errors"
)

// ValidateAndParseOrgID validates the organization ID is present and parses it as a UUID.
func ValidateAndParseOrgID(ctx context.Context, orgID string) (uuid.UUID, error) {
	logger := cmdctx.Logger(ctx)
	errFactory := cmdctx.ErrorFactory(ctx)

	if orgID == "" {
		logger.Error().Msg("No organization ID provided")
		return uuid.UUID{}, errFactory.NewEmptyOrgError()
	}

	orgUUID, err := uuid.Parse(orgID)
	if err != nil {
		return uuid.UUID{}, errFactory.NewInvalidOrgIDError(orgID)
	}

	return orgUUID, nil
}

// ValidateSourceDir checks if the source directory exists and is a directory when reachability is enabled.
func ValidateSourceDir(
	sourceDir string,
	errFactory *errors.ErrorFactory,
) error {
	info, err := os.Stat(sourceDir)
	if err != nil {
		//nolint:wrapcheck // No need to wrap error factory errors.
		return errFactory.NewInvalidSourceDirError(sourceDir)
	}

	if !info.IsDir() {
		//nolint:wrapcheck // No need to wrap error factory errors.
		return errFactory.NewSourceDirIsNotADirectoryError(sourceDir)
	}

	return nil
}
