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

	codeclient "github.com/snyk/code-client-go"
	codeclienthttp "github.com/snyk/code-client-go/http"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/code_workflow"
	"github.com/snyk/go-application-framework/pkg/local_workflows/config_utils"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-os-flows/internal/bundlestore"
	"github.com/snyk/cli-extension-os-flows/internal/errors"
	"github.com/snyk/cli-extension-os-flows/internal/flags"
	"github.com/snyk/cli-extension-os-flows/internal/snykclient"
)

// WorkflowID is the identifier for the Open Source Test workflow.
var WorkflowID = workflow.NewWorkflowIdentifier("test")

// FeatureFlagSBOMTestReachability is used to gate the sbom test reachability feature.
const FeatureFlagSBOMTestReachability = "feature_flag_sbom_test_reachability"

// FeatureFlagRiskScore is used to gate the risk score feature.
const FeatureFlagRiskScore = "feature_flag_experimental_risk_score"

// FeatureFlagRiskScoreInCLI is used to gate the risk score feature in the CLI.
const FeatureFlagRiskScoreInCLI = "feature_flag_experimental_risk_score_in_cli"

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

	// Reachability FF.
	config_utils.AddFeatureFlagToConfig(e, FeatureFlagSBOMTestReachability, "sbomTestReachability")

	// Risk score FFs.
	config_utils.AddFeatureFlagToConfig(e, FeatureFlagRiskScore, "useExperimentalRiskScore")
	config_utils.AddFeatureFlagToConfig(e, FeatureFlagRiskScoreInCLI, "useExperimentalRiskScoreInCLI")

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

	logger.Info().Msg("Getting preferred organization ID")

	orgID := config.GetString(configuration.ORGANIZATION)
	if orgID == "" {
		logger.Error().Msg("No organization ID provided")
		return nil, errFactory.NewEmptyOrgError()
	}

	sbom := config.GetString(flags.FlagSBOM)
	sourceDir := config.GetString(flags.FlagSourceDir)
	sbomTestReachability := config.GetBool(flags.FlagReachability) && sbom != ""

	// Create Snyk client
	httpClient := ictx.GetNetworkAccess().GetHttpClient()
	snykClient := snykclient.NewSnykClient(httpClient, ictx.GetConfiguration().GetString(configuration.API_URL), orgID)

	// Create test client
	testClient, err := testapi.NewTestClient(
		snykClient.GetAPIBaseURL(),
		testapi.WithCustomHTTPClient(snykClient.GetClient()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create test client: %w", err)
	}

	// Route to the appropriate flow based on flags
	switch {
	case sbomTestReachability:
		if !config.GetBool(FeatureFlagSBOMTestReachability) {
			return nil, errFactory.NewFeatureNotPermittedError(FeatureFlagSBOMTestReachability)
		}
		httpClient := codeclienthttp.NewHTTPClient(
			ictx.GetNetworkAccess().GetHttpClient,
			codeclienthttp.WithLogger(logger),
		)

		codeScannerConfig := bundlestore.CodeClientConfig{
			LocalConfiguration: config,
		}

		cScanner := codeclient.NewCodeScanner(
			&codeScannerConfig,
			httpClient,
			codeclient.WithLogger(logger),
		)

		bsClient := bundlestore.NewClient(ictx.GetNetworkAccess().GetHttpClient(), codeScannerConfig, cScanner, logger)
		return RunSbomReachabilityFlow(ctx, errFactory, logger, sbom, sourceDir, bsClient)

	default:
		riskScoreThreshold := config.GetInt(flags.FlagRiskScoreThreshold)
		if !config.GetBool(flags.FlagUnifiedTestAPI) && riskScoreThreshold == -1 {
			logger.Debug().Msg("Using legacy flow since risk score threshold and unified test flags are disabled")
			return code_workflow.EntryPointLegacy(ictx)
		}

		// Unified test flow (with risk score threshold or unified-test flag)

		if riskScoreThreshold >= 0 {
			if !config.GetBool(FeatureFlagRiskScore) {
				return nil, errFactory.NewFeatureNotPermittedError(FeatureFlagRiskScore)
			}
			if !config.GetBool(FeatureFlagRiskScoreInCLI) {
				return nil, errFactory.NewFeatureNotPermittedError(FeatureFlagRiskScoreInCLI)
			}
		}

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
		} else if riskScoreThreshold >= 0 {
			rs := uint16(riskScoreThreshold)
			riskScorePtr = &rs
		}

		var severityThresholdPtr *testapi.Severity
		severityThresholdStr := config.GetString(flags.FlagSeverityThreshold)
		if severityThresholdStr != "" {
			st := testapi.Severity(severityThresholdStr)
			severityThresholdPtr = &st
		}

		return RunUnifiedTestFlow(ctx, testClient, filename, riskScorePtr, severityThresholdPtr, ictx, orgID, errFactory, logger)
	}
}
