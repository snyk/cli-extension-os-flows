package ostest

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/google/uuid"
	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	"github.com/snyk/cli-extension-os-flows/internal/constants"
	internalErrors "github.com/snyk/cli-extension-os-flows/internal/errors"
	"github.com/snyk/cli-extension-os-flows/internal/flags"
	"github.com/snyk/cli-extension-os-flows/internal/settings"
	"github.com/snyk/cli-extension-os-flows/internal/util"
)

// Flow is the type of all the command's flows.
type Flow string

// The list of all available flows.
const (
	LegacyFlow               Flow = "legacy"
	SbomFlow                 Flow = "sbom-flow"
	DepgraphReachabilityFlow Flow = "depgraph-reachability"
	DepgraphFlow             Flow = "depgraph"
)

func validateLegacyCLIOptions(
	fc *FlowConfig,
	errFactory *internalErrors.ErrorFactory,
) error {
	if !fc.ForceLegacyTest && !fc.RequiresLegacy {
		return nil
	}

	invalidFlags := []string{}

	if fc.Unmanaged && fc.Reachability {
		invalidFlags = append(invalidFlags, flags.FlagReachability, flags.FlagUnmanaged)
	} else if fc.Reachability {
		invalidFlags = append(invalidFlags, flags.FlagReachability)
	}

	if fc.RiskScoreThreshold != -1 {
		invalidFlags = append(invalidFlags, flags.FlagRiskScoreThreshold)
	}
	if fc.ReachabilityFilter != "" {
		invalidFlags = append(invalidFlags, flags.FlagReachabilityFilter)
	}
	if fc.SBOM != "" {
		invalidFlags = append(invalidFlags, flags.FlagSBOM)
	}

	for i, flag := range invalidFlags {
		invalidFlags[i] = fmt.Sprintf("--%s", flag)
	}

	if len(invalidFlags) > 0 {
		// User invoking command with a target package, e.g. snyk test lodash
		if fc.TargetPackage != "" {
			//nolint:wrapcheck // No need to wrap error factory errors.
			return errFactory.NewInvalidArgCombinationError(fc.TargetPackage, invalidFlags...)
		}

		//nolint:wrapcheck // No need to wrap error factory errors.
		return errFactory.NewInvalidLegacyFlagError(invalidFlags...)
	}

	return nil
}

func validateRiskScore(riskScoreThreshold int, riskScoreFFsEnabled, ffRiskScore bool, errFactory *internalErrors.ErrorFactory) error {
	if riskScoreThreshold == -1 || riskScoreFFsEnabled {
		return nil
	}

	// The user tried to use a risk score threshold without the required feature flags.
	// Return a specific error for the first missing flag found.
	if !ffRiskScore {
		return errFactory.NewFeatureNotPermittedError(constants.FeatureFlagRiskScore)
	}
	return errFactory.NewFeatureNotPermittedError(constants.FeatureFlagRiskScoreInCLI)
}

func validateReachability(
	ctx context.Context,
	reachability bool,
	sc settings.Client,
	orgUUID uuid.UUID,
	reachabilityFilter string,
	errFactory *internalErrors.ErrorFactory,
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
		//nolint:wrapcheck // No need to wrap error factory errors.
		return errFactory.NewReachabilitySettingsDisabledError(
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
	Unmanaged             bool
	TargetPackage         string
	AllProjects           bool
	TargetFile            string
}

func doesPathExist(path string) (bool, error) {
	_, err := os.Stat(path)
	// If we got no error, it means the path exists.
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, fmt.Errorf("failed to stat path %s: %w", path, err)
}

// ParseFlowConfig reads and parses all flow-related configuration flags.
func ParseFlowConfig(cfg configuration.Configuration) (*FlowConfig, error) {
	ffRiskScore := cfg.GetBool(constants.FeatureFlagRiskScore)
	ffRiskScoreInCLI := cfg.GetBool(constants.FeatureFlagRiskScoreInCLI)
	riskScoreFFsEnabled := ffRiskScore && ffRiskScoreInCLI
	riskScoreThreshold := cfg.GetInt(flags.FlagRiskScoreThreshold)
	riskScoreTest := riskScoreFFsEnabled || riskScoreThreshold != -1

	reachability := cfg.GetBool(flags.FlagReachability)
	sbom := cfg.GetString(flags.FlagSBOM)
	sbomReachabilityTest := reachability && sbom != ""
	reachabilityFilter := cfg.GetString(flags.FlagReachabilityFilter)
	unmanaged := cfg.GetBool(flags.FlagUnmanaged)
	allProjects := cfg.GetBool(flags.FlagAllProjects)
	targetFile := cfg.GetString(flags.FlagFile)
	experimentalFlagSet := cfg.GetBool(configuration.FLAG_EXPERIMENTAL)
	experimentalUvSupport := experimentalFlagSet && cfg.GetBool(constants.EnableExperimentalUvSupportEnvVar)
	forceLegacyTest := cfg.GetBool(constants.ForceLegacyCLIEnvVar)
	requiresLegacy := cfg.GetBool(flags.FlagPrintGraph) ||
		cfg.GetBool(flags.FlagPrintDeps) ||
		cfg.GetBool(flags.FlagPrintDepPaths) ||
		unmanaged
	var targetPackage string

	// The legacy `snyk test` command supports testing packages directly. e.g `snyk test lodash`.
	// The way the command determines if an argument is a package and not a path
	// is by checking if the argument is a valid local path.
	// https://github.com/snyk/cli/blob/c63a7ac7d5dfc9ebfcff077d9922533062873119/src/lib/snyk-test/run-test.ts#L605
	paths := cfg.GetStringSlice(configuration.INPUT_DIRECTORY)
	for _, pth := range paths {
		exists, err := doesPathExist(pth)
		if err != nil {
			return nil, err
		}
		if !exists {
			requiresLegacy = true
			targetPackage = pth
			break
		}
	}

	return &FlowConfig{
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
		Unmanaged:             unmanaged,
		TargetPackage:         targetPackage,
		AllProjects:           allProjects,
		TargetFile:            targetFile,
	}, nil
}

// ShouldUseLegacyFlow determines if the command should route to legacy CLI based on flags.
func ShouldUseLegacyFlow(ctx context.Context, fc *FlowConfig, inputDirs []string) (bool, error) {
	errFactory := cmdctx.ErrorFactory(ctx)
	logger := cmdctx.Logger(ctx)

	if err := validateLegacyCLIOptions(fc, errFactory); err != nil {
		return false, err
	}

	// Check if UV support should trigger, only if env var is set and uv.lock exists.
	uvSupportWithLockFile := fc.ExperimentalUvSupport &&
		util.HasUvLockFileInAnyDir(inputDirs, fc.AllProjects, logger) &&
		util.TargetFileIsUvRelated(fc.TargetFile)

	hasNewFeatures := fc.RiskScoreTest || fc.Reachability || fc.SBOM != "" || fc.ReachabilityFilter != "" || uvSupportWithLockFile
	useLegacy := fc.ForceLegacyTest || fc.RequiresLegacy || !hasNewFeatures

	logger.Debug().Msgf(
		"Using legacy flow: %t. Legacy CLI Env var: %t. SBOM Reachability Test: %t. Risk Score Test: %t. Experimental uv Support: %t.",
		useLegacy,
		fc.ForceLegacyTest,
		fc.SBOMReachabilityTest,
		fc.RiskScoreTest,
		uvSupportWithLockFile,
	)

	return useLegacy, nil
}

// RouteToFlow determines which new flow to use.
func RouteToFlow(ctx context.Context, fc *FlowConfig, orgUUID uuid.UUID, sc settings.Client) (Flow, error) {
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
	case fc.SBOM != "":
		if fc.Reachability && !cfg.GetBool(constants.FeatureFlagSBOMTestReachability) {
			return "", errFactory.NewFeatureNotPermittedError(constants.FeatureFlagSBOMTestReachability)
		}
		return SbomFlow, nil
	case fc.Reachability:
		if !cfg.GetBool(constants.FeatureFlagReachabilityForCLI) {
			//nolint:wrapcheck // No need to wrap error factory errors.
			return "", errFactory.NewReachabilitySettingsDisabledError(
				"In order to run the `test` command with `--reachability=true`, the feature must be enabled in the Snyk Preview.",
			)
		}
		return DepgraphReachabilityFlow, nil
	default:
		return DepgraphFlow, nil
	}
}
