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

	"github.com/google/uuid"
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
	"github.com/snyk/cli-extension-os-flows/internal/reachability"
	"github.com/snyk/cli-extension-os-flows/internal/snykclient"
)

// WorkflowID is the identifier for the Open Source Test workflow.
var WorkflowID = workflow.NewWorkflowIdentifier("test")

// FeatureFlagReachabilityForCLI is used to gate the legacy monitor reachability feature.
const FeatureFlagReachabilityForCLI = "feature_flag_monitor_reachability"

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
	config_utils.AddFeatureFlagToConfig(e, FeatureFlagReachabilityForCLI, "reachabilityForCli")
	config_utils.AddFeatureFlagToConfig(e, FeatureFlagSBOMTestReachability, "sbomTestReachability")

	// Risk score FFs.
	config_utils.AddFeatureFlagToConfig(e, FeatureFlagRiskScore, "useExperimentalRiskScore")
	config_utils.AddFeatureFlagToConfig(e, FeatureFlagRiskScoreInCLI, "useExperimentalRiskScoreInCLI")

	return nil
}

func setupBundlestoreClient(ictx workflow.InvocationContext, logger *zerolog.Logger) bundlestore.Client {
	config := ictx.GetConfiguration()

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

	return bsClient
}

// setupSBOMReachabilityFlow sets up and runs the SBOM reachability flow.
func setupSBOMReachabilityFlow(
	ctx context.Context,
	ictx workflow.InvocationContext,
	testClient testapi.TestClient,
	orgID string,
	errFactory *errors.ErrorFactory,
	logger *zerolog.Logger,
	sbom, sourceDir string,
	localPolicy *testapi.LocalPolicy,
) ([]workflow.Data, error) {
	config := ictx.GetConfiguration()

	if !config.GetBool(FeatureFlagSBOMTestReachability) {
		return nil, errFactory.NewFeatureNotPermittedError(FeatureFlagSBOMTestReachability)
	}

	bsClient := setupBundlestoreClient(ictx, logger)
	return RunSbomReachabilityFlow(ctx, ictx, testClient, errFactory, logger, sbom, sourceDir, bsClient, orgID, localPolicy)
}

func setupDepgraphReachabilityFlow(ctx context.Context, ictx workflow.InvocationContext, testClient testapi.TestClient, orgID, sourceDir string, errFactory *errors.ErrorFactory, logger *zerolog.Logger, localPolicy *testapi.LocalPolicy) ([]workflow.Data, error) {
	config := ictx.GetConfiguration()

	if !config.GetBool(FeatureFlagReachabilityForCLI) {
		return nil, errFactory.NewFeatureNotPermittedError(FeatureFlagReachabilityForCLI)
	}

	orgUUID, err := uuid.Parse(orgID)
	if err != nil {
		return nil, fmt.Errorf("orgID is invalid: %w", err)
	}

	bsClient := setupBundlestoreClient(ictx, logger)
	rc := reachability.NewClient(ictx.GetNetworkAccess().GetHttpClient(), reachability.Config{
		BaseURL: config.GetString(configuration.API_URL),
	})

	_, err = reachability.GetReachabilityID(ctx, orgUUID, sourceDir, rc, bsClient)
	if err != nil {
		return nil, fmt.Errorf("failed to analyse source code: %w", err)
	}

	return RunUnifiedTestFlow(ctx, ictx, testClient, orgID, errFactory, logger, localPolicy)
}

// CreateLocalPolicy will create a local policy only if risk score or severity threshold are specified in the config.
func CreateLocalPolicy(config configuration.Configuration, logger *zerolog.Logger) *testapi.LocalPolicy {
	var riskScoreThreshold *uint16
	riskScoreThresholdInt := config.GetInt(flags.FlagRiskScoreThreshold)
	if riskScoreThresholdInt >= math.MaxUint16 {
		// the API will enforce a range from the test spec
		logger.Warn().Msgf("Risk score threshold %d exceeds maximum uint16 value. Setting to maximum.", riskScoreThresholdInt)
		maxVal := uint16(math.MaxUint16)
		riskScoreThreshold = &maxVal
	} else if riskScoreThresholdInt >= 0 {
		rs := uint16(riskScoreThresholdInt)
		riskScoreThreshold = &rs
	}

	var severityThreshold *testapi.Severity
	severityThresholdStr := config.GetString(flags.FlagSeverityThreshold)
	if severityThresholdStr != "" {
		st := testapi.Severity(severityThresholdStr)
		severityThreshold = &st
	}

	if riskScoreThreshold == nil && severityThreshold == nil {
		return nil
	}

	return &testapi.LocalPolicy{
		RiskScoreThreshold: riskScoreThreshold,
		SeverityThreshold:  severityThreshold,
	}
}

// OSWorkflow is the entry point for the Open Source Test workflow.
func OSWorkflow(
	ictx workflow.InvocationContext,
	_ []workflow.Data,
) ([]workflow.Data, error) {
	executionPath, err := routeWorkflow(ictx)
	if err != nil {
		return nil, err
	}

	return executeWorkflow(executionPath, ictx)
}

type WorkflowExecutionPath string

const (
	SBOM_REACHABILITY_TEST       WorkflowExecutionPath = "SBOM_REACHABILITY_TEST"
	LEGACY_DEPGRAPH_REACHABILITY WorkflowExecutionPath = "LEGACY_DEPGRAPH_REACHABILITY"
	UNIFIED_TEST_FLOW            WorkflowExecutionPath = "UNIFIED_TEST_FLOW"
	LEGACY_TEST                  WorkflowExecutionPath = "LEGACY_TEST"
)

func routeWorkflow(ictx workflow.InvocationContext) (WorkflowExecutionPath, error) {
	config := ictx.GetConfiguration()
	logger := ictx.GetEnhancedLogger()
	errFactory := errors.NewErrorFactory(logger)

	riskScoreThreshold := config.GetInt(flags.FlagRiskScoreThreshold)
	if riskScoreThreshold != -1 {
		if !config.GetBool(FeatureFlagRiskScore) {
			return "", errFactory.NewFeatureNotPermittedError(FeatureFlagRiskScore)
		}
		if !config.GetBool(FeatureFlagRiskScoreInCLI) {
			return "", errFactory.NewFeatureNotPermittedError(FeatureFlagRiskScoreInCLI)
		}
		return "", nil
	}

	reachability := config.GetBool(flags.FlagReachability)
	sbom := config.GetString(flags.FlagSBOM)
	sbomReachabilityTest := reachability && sbom != ""

	forceLegacyTest := config.GetBool(ForceLegacyCLIEnvVar)

	if sbomReachabilityTest {
		return SBOM_REACHABILITY_TEST, nil
	}

	if reachability {
		return LEGACY_DEPGRAPH_REACHABILITY, nil
	}

	if forceLegacyTest {
		logger.Debug().Msgf(
			"Using legacy flow. Legacy CLI Env var: %t. SBOM Reachability Test: %t. Risk Score Test: %d.",
			forceLegacyTest,
			sbomReachabilityTest,
			riskScoreThreshold,
		)
		return LEGACY_TEST, nil
	}

	return UNIFIED_TEST_FLOW, nil
}

func executeWorkflow(executionPath WorkflowExecutionPath, ictx workflow.InvocationContext) ([]workflow.Data, error) {
	config := ictx.GetConfiguration()
	ctx := context.Background()
	logger := ictx.GetEnhancedLogger()
	errFactory := errors.NewErrorFactory(logger)

	logger.Info().Msg("Getting preferred organization ID")
	orgID := config.GetString(configuration.ORGANIZATION)
	if orgID == "" {
		logger.Error().Msg("No organization ID provided")
		return nil, errFactory.NewEmptyOrgError()
	}

	// Reachability
	sourceDir := config.GetString(flags.FlagSourceDir)

	localPolicy := CreateLocalPolicy(config, logger)

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

	switch executionPath {
	case SBOM_REACHABILITY_TEST:
		sbom := config.GetString(flags.FlagSBOM)
		return setupSBOMReachabilityFlow(ctx, ictx, testClient, orgID, errFactory, logger, sbom, sourceDir, localPolicy)
	case LEGACY_DEPGRAPH_REACHABILITY:
		return setupDepgraphReachabilityFlow(ctx, ictx, testClient, orgID, sourceDir, errFactory, logger, localPolicy)
	case UNIFIED_TEST_FLOW:
		return RunUnifiedTestFlow(ctx, ictx, testClient, orgID, errFactory, logger, localPolicy)
	case LEGACY_TEST:
		return code_workflow.EntryPointLegacy(ictx)
	default:
		return nil, fmt.Errorf("unknown execution path: %s", executionPath)
	}
}
