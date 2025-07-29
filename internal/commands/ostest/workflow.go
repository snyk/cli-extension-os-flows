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
	"time"

	"github.com/rs/zerolog"
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

// ForceLegacyCLIEnvVar is an internal environment variable to force the legacy CLI flow.
const ForceLegacyCLIEnvVar = "SNYK_FORCE_LEGACY_CLI"

// PollInterval is the polling interval for the test API. It is exported to be configurable in tests.
var PollInterval = 2 * time.Second

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

// setupSBOMReachabilityFlow sets up and runs the SBOM reachability flow.
func setupSBOMReachabilityFlow(
	ctx context.Context,
	ictx workflow.InvocationContext,
	errFactory *errors.ErrorFactory,
	logger *zerolog.Logger,
	sbom, sourceDir string,
) ([]workflow.Data, error) {
	config := ictx.GetConfiguration()

	if !config.GetBool(FeatureFlagSBOMTestReachability) {
		return nil, errFactory.NewFeatureNotPermittedError(FeatureFlagSBOMTestReachability)
	}

	httpCodeClient := codeclienthttp.NewHTTPClient(
		ictx.GetNetworkAccess().GetHttpClient,
		codeclienthttp.WithLogger(logger),
	)

	codeScannerConfig := bundlestore.CodeClientConfig{
		LocalConfiguration: config,
	}

	cScanner := codeclient.NewCodeScanner(
		&codeScannerConfig,
		httpCodeClient,
		codeclient.WithLogger(logger),
	)

	bsClient := bundlestore.NewClient(ictx.GetNetworkAccess().GetHttpClient(), codeScannerConfig, cScanner, logger)
	return RunSbomReachabilityFlow(ctx, errFactory, logger, sbom, sourceDir, bsClient)
}

// setupDefaultTestFlow sets up and runs the default test flow with risk score and severity thresholds.
func setupDefaultTestFlow(
	ctx context.Context,
	ictx workflow.InvocationContext,
	testClient testapi.TestClient,
	orgID string,
	errFactory *errors.ErrorFactory,
	logger *zerolog.Logger,
	riskScoreThreshold int,
) ([]workflow.Data, error) {
	config := ictx.GetConfiguration()

	// Risk Score FFs
	ffRiskScore := config.GetBool(FeatureFlagRiskScore)
	ffRiskScoreInCLI := config.GetBool(FeatureFlagRiskScoreInCLI)
	riskScoreFFsEnabled := ffRiskScore && ffRiskScoreInCLI

	if riskScoreThreshold != -1 && !riskScoreFFsEnabled {
		// The user tried to use a risk score threshold without the required feature flags.
		// Return a specific error for the first missing flag found.
		if !ffRiskScore {
			return nil, errFactory.NewFeatureNotPermittedError(FeatureFlagRiskScore)
		}
		return nil, errFactory.NewFeatureNotPermittedError(FeatureFlagRiskScoreInCLI)
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

	return RunUnifiedTestFlow(ctx, ictx, testClient, riskScorePtr, severityThresholdPtr, orgID, errFactory, logger)
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

	// SBOM Test w/ Reachability
	sbom := config.GetString(flags.FlagSBOM)
	sourceDir := config.GetString(flags.FlagSourceDir)
	sbomReachabilityTest := config.GetBool(flags.FlagReachability) && sbom != ""

	// Risk Score
	ffRiskScore := config.GetBool(FeatureFlagRiskScore)
	ffRiskScoreInCLI := config.GetBool(FeatureFlagRiskScoreInCLI)
	riskScoreFFsEnabled := ffRiskScore && ffRiskScoreInCLI
	riskScoreThreshold := config.GetInt(flags.FlagRiskScoreThreshold)
	riskScoreTest := riskScoreFFsEnabled || riskScoreThreshold != -1

	forceLegacyTest := config.GetBool(ForceLegacyCLIEnvVar)
	// Legacy test fallthrough
	if forceLegacyTest || (!sbomReachabilityTest && !riskScoreTest) {
		logger.Debug().Msgf(
			"Using legacy flow. Legacy CLI Env var: %t. SBOM Reachability Test: %t. Risk Score Test: %t.",
			forceLegacyTest,
			sbomReachabilityTest,
			riskScoreTest,
		)
		return code_workflow.EntryPointLegacy(ictx)
	}

	logger.Info().Msg("Getting preferred organization ID")
	orgID := config.GetString(configuration.ORGANIZATION)
	if orgID == "" {
		logger.Error().Msg("No organization ID provided")
		return nil, errFactory.NewEmptyOrgError()
	}

	// Create Snyk client
	httpClient := ictx.GetNetworkAccess().GetHttpClient()
	snykClient := snykclient.NewSnykClient(httpClient, ictx.GetConfiguration().GetString(configuration.API_URL), orgID)

	// Create test client
	testClient, err := testapi.NewTestClient(
		snykClient.GetAPIBaseURL(),
		testapi.WithPollInterval(PollInterval),
		testapi.WithCustomHTTPClient(snykClient.GetClient()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create test client: %w", err)
	}

	// Route to the appropriate flow based on flags
	switch {
	case sbomReachabilityTest:
		return setupSBOMReachabilityFlow(ctx, ictx, errFactory, logger, sbom, sourceDir)
	default:
		return setupDefaultTestFlow(ctx, ictx, testClient, orgID, errFactory, logger, riskScoreThreshold)
	}
}
