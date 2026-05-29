package common

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/cli-extension-os-flows/internal/commands/clientsetup"
	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	"github.com/snyk/cli-extension-os-flows/internal/constants"
	"github.com/snyk/cli-extension-os-flows/internal/reachability/sources"
	"github.com/snyk/cli-extension-os-flows/pkg/flags"
)

// ShouldRunReachability reports whether the source directory contains any files
// in a reachability-supported language. On error inspecting the directory we
// fall through (return true) so a transient IO issue never costs the user a
// scan they asked for — the existing upload path will surface the real error.
func ShouldRunReachability(sourceDir string, logger *zerolog.Logger) bool {
	hasSources, err := sources.HasSupportedSources(sourceDir, logger)
	if err != nil {
		logger.Warn().Err(err).Str("sourceDir", sourceDir).Msg("Failed to inspect source directory for reachability; proceeding with upload")
		return true
	}
	if !hasSources {
		logger.Info().
			Str("sourceDir", sourceDir).
			Interface("supportedLanguages", sources.SupportedExtensionsByLanguage).
			Msg("No reachability-supported source files found; skipping upload")
	}
	return hasSources
}

// ResolveMonitorReachabilityOpts determines the reachability options for the monitor flow.
// It checks feature flags and org settings, returning an error when reachability is requested but unavailable.
func ResolveMonitorReachabilityOpts(ctx context.Context, cfg configuration.Configuration, orgUUID uuid.UUID, inputDir string) (*ReachabilityOpts, error) {
	errFactory := cmdctx.ErrorFactory(ctx)

	if !cfg.GetBool(flags.FlagReachability) {
		return nil, nil //nolint:nilnil // nil opts with nil error signals reachability is not requested.
	}

	if !cfg.GetBool(constants.FeatureFlagReachabilityForCLI) {
		//nolint:wrapcheck // No need to wrap error factory errors.
		return nil, errFactory.NewReachabilitySettingsDisabledError(
			"In order to run the `monitor` command with `--reachability=true`, the feature must be enabled in the Snyk Preview.",
		)
	}

	sc := clientsetup.SetupSettingsClient(ctx)
	isReachEnabled, settingsErr := sc.IsReachabilityEnabled(ctx, orgUUID)
	if settingsErr != nil {
		return nil, fmt.Errorf("failed to check reachability settings: %w", settingsErr)
	}
	if !isReachEnabled {
		//nolint:wrapcheck // No need to wrap error factory errors.
		return nil, errFactory.NewReachabilitySettingsDisabledError(
			"In order to run the `monitor` command with `--reachability=true`, the reachability settings must be enabled.",
		)
	}

	sourceDir := GetSourceDir(cfg, inputDir)
	if validErr := ValidateSourceDir(sourceDir, errFactory); validErr != nil {
		return nil, validErr
	}

	return &ReachabilityOpts{SourceDir: sourceDir}, nil
}
