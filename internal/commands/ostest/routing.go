package ostest

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/snyk/error-catalog-golang-public/opensource/ecosystems"
	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	"github.com/snyk/cli-extension-os-flows/internal/constants"
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

// FlowConfig holds parsed configuration for flow routing decisions.
type FlowConfig struct {
	FFRiskScore           bool
	FFRiskScoreInCLI      bool
	RiskScoreFFsEnabled   bool
	RiskScoreThreshold    int
	RiskScoreTest         bool
	Reachability          bool
	SBOM                  string
	SBOMReachabilityTest  bool
	ReachabilityFilter    string
	ExperimentalUvSupport bool
	ForceLegacyTest       bool
	RequiresLegacy        bool
}

// ParseFlowConfig reads and parses all flow-related configuration flags.
func ParseFlowConfig(cfg configuration.Configuration) FlowConfig {
	ffRiskScore := cfg.GetBool(FeatureFlagRiskScore)
	ffRiskScoreInCLI := cfg.GetBool(FeatureFlagRiskScoreInCLI)
	riskScoreFFsEnabled := ffRiskScore && ffRiskScoreInCLI
	riskScoreThreshold := cfg.GetInt(flags.FlagRiskScoreThreshold)
	riskScoreTest := riskScoreFFsEnabled || riskScoreThreshold != -1

	reachability := cfg.GetBool(flags.FlagReachability)
	sbom := cfg.GetString(flags.FlagSBOM)
	sbomReachabilityTest := reachability && sbom != ""
	reachabilityFilter := cfg.GetString(flags.FlagReachabilityFilter)

	experimentalUvSupport := cfg.GetBool(constants.EnableExperimentalUvSupportEnvVar)
	forceLegacyTest := cfg.GetBool(constants.ForceLegacyCLIEnvVar)
	requiresLegacy := cfg.GetBool(flags.FlagPrintGraph) ||
		cfg.GetBool(flags.FlagPrintDeps) ||
		cfg.GetBool(flags.FlagPrintDepPaths) ||
		cfg.GetBool(flags.FlagUnmanaged)

	return FlowConfig{
		FFRiskScore:           ffRiskScore,
		FFRiskScoreInCLI:      ffRiskScoreInCLI,
		RiskScoreFFsEnabled:   riskScoreFFsEnabled,
		RiskScoreThreshold:    riskScoreThreshold,
		RiskScoreTest:         riskScoreTest,
		Reachability:          reachability,
		SBOM:                  sbom,
		SBOMReachabilityTest:  sbomReachabilityTest,
		ReachabilityFilter:    reachabilityFilter,
		ExperimentalUvSupport: experimentalUvSupport,
		ForceLegacyTest:       forceLegacyTest,
		RequiresLegacy:        requiresLegacy,
	}
}

// ShouldUseLegacyFlow determines if the command should route to legacy CLI based on flags.
func ShouldUseLegacyFlow(ctx context.Context, fc FlowConfig) (bool, error) {
	errFactory := cmdctx.ErrorFactory(ctx)
	logger := cmdctx.Logger(ctx)

	err := validateLegacyCLIOptions(
		fc.ForceLegacyTest,
		fc.RequiresLegacy,
		fc.RiskScoreThreshold,
		fc.Reachability,
		fc.SBOM,
		fc.ReachabilityFilter,
		errFactory,
	)
	if err != nil {
		return false, err
	}

	hasNewFeatures := fc.RiskScoreTest || fc.Reachability || fc.SBOM != "" || fc.ReachabilityFilter != "" || fc.ExperimentalUvSupport
	useLegacy := fc.ForceLegacyTest || fc.RequiresLegacy || !hasNewFeatures

	logger.Debug().Msgf(
		"Using legacy flow: %t. Legacy CLI Env var: %t. SBOM Reachability Test: %t. Risk Score Test: %t. Experimental uv Support: %t.",
		useLegacy,
		fc.ForceLegacyTest,
		fc.SBOMReachabilityTest,
		fc.RiskScoreTest,
		fc.ExperimentalUvSupport,
	)

	return useLegacy, nil
}

// RouteToFlow determines which new flow to use.
func RouteToFlow(ctx context.Context, fc FlowConfig, orgUUID uuid.UUID, sc settings.Client) (Flow, error) {
	cfg := cmdctx.Config(ctx)
	errFactory := cmdctx.ErrorFactory(ctx)

	err := validateRiskScore(fc.RiskScoreThreshold, fc.RiskScoreFFsEnabled, fc.FFRiskScore, errFactory)
	if err != nil {
		return "", err
	}

	err = validateReachability(ctx, fc.Reachability, sc, orgUUID, fc.ReachabilityFilter, errFactory)
	if err != nil {
		return "", err
	}

	switch {
	case fc.SBOMReachabilityTest:
		if !cfg.GetBool(FeatureFlagSBOMTestReachability) {
			return "", errFactory.NewFeatureNotPermittedError(FeatureFlagSBOMTestReachability)
		}
		return SBOMReachabilityFlow, nil
	case fc.Reachability:
		if !cfg.GetBool(FeatureFlagReachabilityForCLI) {
			return "", errFactory.NewFeatureNotPermittedError(FeatureFlagReachabilityForCLI)
		}
		return DepgraphReachabilityFlow, nil
	default:
		return DepgraphFlow, nil
	}
}
