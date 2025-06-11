// Package ostest implements the "test" command for the Snyk CLI's Open Source security testing.
//
// This package provides the core functionality for running Open Source security tests
// through the Snyk CLI. It handles workflow registration, command-line flag parsing,
// and implements the test execution logic with support for both legacy and new unified test flows.
//
// The package is primarily used by the main osflows package to register and expose
// the test command to the Snyk CLI framework.
package ostest

import (
	"context"
	"fmt"
	"math"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/code_workflow"
	"github.com/snyk/go-application-framework/pkg/local_workflows/config_utils"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-os-flows/internal/errors"
	"github.com/snyk/cli-extension-os-flows/internal/flags"
)

// WorkflowID is the identifier for the Open Source Test workflow.
var WorkflowID = workflow.NewWorkflowIdentifier("test")

// FeatureFlagSBOMTestReachability is used to gate the sbom test reachability feature.
const FeatureFlagSBOMTestReachability = "feature_flag_sbom_test_reachability"

// RegisterWorkflows registers the "test" workflow.
func RegisterWorkflows(e workflow.Engine) error {
	// Check if workflow already exists
	if _, ok := e.GetWorkflow(WorkflowID); ok {
		return fmt.Errorf("workflow with ID %s already exists", WorkflowID)
	}

	osTestFlagset := flags.OSTestFlagSet()

	c := workflow.ConfigurationOptionsFromFlagset(osTestFlagset)

	if _, err := e.Register(WorkflowID, c, OSWorkflow); err != nil {
		return fmt.Errorf("error while registering test workflow: %w", err)
	}

	// Reachability ff.
	config_utils.AddFeatureFlagToConfig(e, FeatureFlagSBOMTestReachability, "sbomTestReachability")

	return nil
}

// OSWorkflow is the entry point for the Open Source Test workflow.
func OSWorkflow(
	ictx workflow.InvocationContext,
	_ []workflow.Data,
) ([]workflow.Data, error) {
	config := ictx.GetConfiguration()
	logger := ictx.GetEnhancedLogger()
	errFactory := errors.NewErrorFactory(logger)
	ctx := context.Background()
	logger.Println("OS Test workflow start")

	logger.Info().Msg("Getting preferred organization ID")

	orgID := config.GetString(configuration.ORGANIZATION)
	if orgID == "" {
		logger.Error().Msg("No organization ID provided")
		return nil, errFactory.NewEmptyOrgError()
	}

	sbom := config.GetString(flags.FlagSBOM)
	sourceDir := config.GetString(flags.FlagSourceDir)
	sbomTestReachability := config.GetBool(flags.FlagReachability) && sbom != ""

	// Route to the appropriate flow based on flags
	switch {
	case sbomTestReachability:
		if !config.GetBool(FeatureFlagSBOMTestReachability) {
			return nil, errFactory.NewFeatureNotPermittedError(FeatureFlagSBOMTestReachability)
		}
		return runReachabilityFlow(ctx, config, errFactory, ictx, logger, sbom, sourceDir)

	default:
		riskScoreThreshold := config.GetInt(flags.FlagRiskScoreThreshold)
		if !config.GetBool(flags.FlagUnifiedTestAPI) && riskScoreThreshold == -1 {
			logger.Debug().Msg("Using legacy flow since risk score threshold and unified test flags are disabled")
			return code_workflow.EntryPointLegacy(ictx)
		}

		// Unified test flow (with risk score threshold or unified-test flag)
		filename := config.GetString(flags.FlagFile)
		if filename == "" {
			logger.Error().Msg("No file specified for testing")
			return nil, errFactory.NewMissingFilenameFlagError()
		}

		var riskScorePtr *uint16
		if riskScoreThreshold >= math.MaxUint16 {
			// the API will enforce a range from the test spec
			logger.Warn().Msgf("Risk score threshold %d exceeds maximum uint16 value. Setting to maximum.", riskScoreThreshold)
			maxVal := uint16(math.MaxUint16)
			riskScorePtr = &maxVal
		}
		if riskScoreThreshold >= 0 {
			rs := uint16(riskScoreThreshold)
			riskScorePtr = &rs
		}

		return runUnifiedTestFlow(riskScorePtr, config, logger, errFactory)
	}
}

// runUnifiedTestFlow handles the unified test API flow.
func runUnifiedTestFlow(
	riskScoreThreshold *uint16,
	config configuration.Configuration,
	logger *zerolog.Logger,
	errFactory *errors.ErrorFactory,
) ([]workflow.Data, error) {
	// TODO: Implement new workflow with risk score calculation
	logger.Println("OS Test workflow not yet implemented")
	logger.Println("Risk score threshold	= ", riskScoreThreshold)
	logger.Println("Force Unified Test API 	= ", config.GetBool(flags.FlagUnifiedTestAPI))

	return nil, errFactory.NewNotImplementedError()
}

// runReachabilityFlow handles the reachability analysis flow.
func runReachabilityFlow(
	ctx context.Context,
	config configuration.Configuration,
	errFactory *errors.ErrorFactory,
	ictx workflow.InvocationContext,
	logger *zerolog.Logger,
	sbomPath string,
	sourceCodePath string,
) ([]workflow.Data, error) {
	return sbomTestReachability(ctx, config, errFactory, ictx, logger, sbomPath, sourceCodePath)
}
