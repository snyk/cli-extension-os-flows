package ostest

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/snyk/error-catalog-golang-public/opensource/ecosystems"

	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	"github.com/snyk/cli-extension-os-flows/internal/errors"
	"github.com/snyk/cli-extension-os-flows/internal/flags"
	"github.com/snyk/cli-extension-os-flows/internal/settings"
)

// Flow is the type of all the command's flows.
type Flow string

// The list of all available flows.
const (
	LegacyFlow               Flow = "legacy"
	SBOMReachabilityFlow     Flow = "sbom-reachability"
	DepgraphReachabilityFlow Flow = "depgraph-reachability"
	DepgraphFlow             Flow = "depgraph"
)

func validateLegacyCLIOptions(
	forceLegacyTest,
	requiresLegacy bool,
	riskScoreThreshold int,
	reachability bool,
	sbom,
	reachabilityFilter string,
	errFactory *errors.ErrorFactory,
) error {
	if !forceLegacyTest && !requiresLegacy {
		return nil
	}

	if riskScoreThreshold != -1 {
		//nolint:wrapcheck // No need to wrap error factory errors.
		return errFactory.NewInvalidLegacyFlagError("--risk-score-threshold")
	}
	if reachability {
		//nolint:wrapcheck // No need to wrap error factory errors.
		return errFactory.NewInvalidLegacyFlagError("--reachability")
	}
	if reachabilityFilter != "" {
		//nolint:wrapcheck // No need to wrap error factory errors.
		return errFactory.NewInvalidLegacyFlagError("--reachability-filter")
	}
	if sbom != "" {
		//nolint:wrapcheck // No need to wrap error factory errors.
		return errFactory.NewInvalidLegacyFlagError("--sbom")
	}

	return nil
}

func validateRiskScore(riskScoreThreshold int, riskScoreFFsEnabled, ffRiskScore bool, errFactory *errors.ErrorFactory) error {
	if riskScoreThreshold == -1 || riskScoreFFsEnabled {
		return nil
	}

	// The user tried to use a risk score threshold without the required feature flags.
	// Return a specific error for the first missing flag found.
	if !ffRiskScore {
		return errFactory.NewFeatureNotPermittedError(FeatureFlagRiskScore)
	}
	return errFactory.NewFeatureNotPermittedError(FeatureFlagRiskScoreInCLI)
}

func validateReachability(
	ctx context.Context,
	reachability bool,
	sc settings.Client,
	orgUUID uuid.UUID,
	reachabilityFilter string,
	errFactory *errors.ErrorFactory,
) error {
	if !reachability {
		// Validate that --reachability-filter is not used without --reachability
		if reachabilityFilter != "" {
			return errFactory.NewReachabilityFilterWithoutReachabilityError() //nolint:wrapcheck // error catalog already contains details
		}
		return nil
	}

	isReachEnabled, err := sc.IsReachabilityEnabled(ctx, orgUUID)
	if err != nil {
		return fmt.Errorf("failed to check reachability settings: %w", err)
	}

	if !isReachEnabled {
		return ecosystems.NewReachabilitySettingDisabledError(
			"In order to run the `test` command with `--reachability`, the reachability settings must be enabled.",
		)
	}

	return nil
}

// RouteToFlow will determine which flow to route the command to, based on the provided configuration.
func RouteToFlow(ctx context.Context, orgUUID uuid.UUID, sc settings.Client) (Flow, error) { //nolint:gocyclo // The cyclomatic complexity is acceptable.
	cfg := cmdctx.Config(ctx)
	logger := cmdctx.Logger(ctx)
	errFactory := cmdctx.ErrorFactory(ctx)

	ffRiskScore := cfg.GetBool(FeatureFlagRiskScore)
	ffRiskScoreInCLI := cfg.GetBool(FeatureFlagRiskScoreInCLI)
	riskScoreFFsEnabled := ffRiskScore && ffRiskScoreInCLI
	riskScoreThreshold := cfg.GetInt(flags.FlagRiskScoreThreshold)
	riskScoreTest := riskScoreFFsEnabled || riskScoreThreshold != -1

	reachability := cfg.GetBool(flags.FlagReachability)
	sbom := cfg.GetString(flags.FlagSBOM)
	sbomReachabilityTest := reachability && sbom != ""
	reachabilityFilter := cfg.GetString(flags.FlagReachabilityFilter)

	forceLegacyTest := cfg.GetBool(ForceLegacyCLIEnvVar)
	requiresLegacy := cfg.GetBool(flags.FlagPrintGraph) ||
		cfg.GetBool(flags.FlagPrintDeps) ||
		cfg.GetBool(flags.FlagPrintDepPaths) ||
		cfg.GetBool(flags.FlagUnmanaged)

	err := validateLegacyCLIOptions(
		forceLegacyTest,
		requiresLegacy,
		riskScoreThreshold,
		reachability,
		sbom,
		reachabilityFilter,
		errFactory,
	)
	if err != nil {
		return "", err
	}

	err = validateRiskScore(riskScoreThreshold, riskScoreFFsEnabled, ffRiskScore, errFactory)
	if err != nil {
		return "", err
	}

	err = validateReachability(ctx, reachability, sc, orgUUID, reachabilityFilter, errFactory)
	if err != nil {
		return "", err
	}

	switch {
	case forceLegacyTest || requiresLegacy || (!riskScoreTest && !reachability && sbom == ""):
		logger.Debug().Msgf(
			"Using legacy flow. Legacy CLI Env var: %t. SBOM Reachability Test: %t. Risk Score Test: %t.",
			forceLegacyTest,
			sbomReachabilityTest,
			riskScoreTest,
		)
		return LegacyFlow, nil
	case sbomReachabilityTest:
		if !cfg.GetBool(FeatureFlagSBOMTestReachability) {
			return "", errFactory.NewFeatureNotPermittedError(FeatureFlagSBOMTestReachability)
		}
		return SBOMReachabilityFlow, nil
	case reachability:
		if !cfg.GetBool(FeatureFlagReachabilityForCLI) {
			return "", errFactory.NewFeatureNotPermittedError(FeatureFlagReachabilityForCLI)
		}
		return DepgraphReachabilityFlow, nil
	default:
		return DepgraphFlow, nil
	}
}
