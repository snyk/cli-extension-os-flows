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
	"github.com/snyk/error-catalog-golang-public/opensource/ecosystems"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/code_workflow"
	"github.com/snyk/go-application-framework/pkg/local_workflows/config_utils"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-os-flows/internal/bundlestore"
	"github.com/snyk/cli-extension-os-flows/internal/errors"
	"github.com/snyk/cli-extension-os-flows/internal/flags"
	"github.com/snyk/cli-extension-os-flows/internal/reachability"
	"github.com/snyk/cli-extension-os-flows/internal/settings"
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

func setupTestClient(ictx workflow.InvocationContext) (testapi.TestClient, error) {
	config := ictx.GetConfiguration()
	httpClient := ictx.GetNetworkAccess().GetHttpClient()
	snykClient := snykclient.NewSnykClient(httpClient, config.GetString(configuration.API_URL), config.GetString(configuration.ORGANIZATION))

	testClient, err := testapi.NewTestClient(
		snykClient.GetAPIBaseURL(),
		testapi.WithPollInterval(PollInterval),
		testapi.WithCustomHTTPClient(snykClient.GetClient()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create test client: %w", err)
	}

	return testClient, nil
}

func setupSettingsClient(ictx workflow.InvocationContext) settings.Client {
	config := ictx.GetConfiguration()
	sc := settings.NewClient(ictx.GetNetworkAccess().GetHttpClient(), settings.Config{BaseURL: config.GetString(configuration.API_URL)})

	return sc
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

// handleSBOMReachabilityFlow sets up and runs the SBOM reachability flow.
func handleSBOMReachabilityFlow(
	ctx context.Context,
	ictx workflow.InvocationContext,
	testClient testapi.TestClient,
	orgID, sbom, sourceDir string,
	errFactory *errors.ErrorFactory,
	logger *zerolog.Logger,
	localPolicy *testapi.LocalPolicy,
) ([]workflow.Data, error) {
	config := ictx.GetConfiguration()

	if !config.GetBool(FeatureFlagSBOMTestReachability) {
		return nil, errFactory.NewFeatureNotPermittedError(FeatureFlagSBOMTestReachability)
	}

	bsClient := setupBundlestoreClient(ictx, logger)
	return RunSbomReachabilityFlow(ctx, ictx, testClient, errFactory, logger, sbom, sourceDir, bsClient, orgID, localPolicy)
}

func handleDepgraphReachabilityFlow(
	ctx context.Context,
	ictx workflow.InvocationContext,
	testClient testapi.TestClient,
	orgUUID uuid.UUID,
	sourceDir string,
	errFactory *errors.ErrorFactory,
	logger *zerolog.Logger,
	localPolicy *testapi.LocalPolicy,
) ([]workflow.Data, error) {
	config := ictx.GetConfiguration()

	if !config.GetBool(FeatureFlagReachabilityForCLI) {
		return nil, errFactory.NewFeatureNotPermittedError(FeatureFlagReachabilityForCLI)
	}

	bsClient := setupBundlestoreClient(ictx, logger)
	rc := reachability.NewClient(ictx.GetNetworkAccess().GetHttpClient(), reachability.Config{
		BaseURL: config.GetString(configuration.API_URL),
	})

	scanID, err := reachability.GetReachabilityID(ctx, orgUUID, sourceDir, rc, bsClient)
	if err != nil {
		return nil, fmt.Errorf("failed to analyze source code: %w", err)
	}

	return RunUnifiedTestFlow(ctx, ictx, testClient, orgUUID.String(), errFactory, logger, localPolicy, &scanID)
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
func OSWorkflow( //nolint:gocyclo // Will be addressed in a refactor.
	ictx workflow.InvocationContext,
	_ []workflow.Data,
) ([]workflow.Data, error) {
	config := ictx.GetConfiguration()
	logger := ictx.GetEnhancedLogger()
	errFactory := errors.NewErrorFactory(logger)
	ctx := context.Background()

	// Reachability
	reachability := config.GetBool(flags.FlagReachability)
	sourceDir := config.GetString(flags.FlagSourceDir)
	if sourceDir == "" {
		sourceDir = "."
	}

	// SBOM Test w/ Reachability
	sbom := config.GetString(flags.FlagSBOM)
	sbomReachabilityTest := reachability && sbom != ""

	// Risk Score
	ffRiskScore := config.GetBool(FeatureFlagRiskScore)
	ffRiskScoreInCLI := config.GetBool(FeatureFlagRiskScoreInCLI)
	riskScoreFFsEnabled := ffRiskScore && ffRiskScoreInCLI
	riskScoreThreshold := config.GetInt(flags.FlagRiskScoreThreshold)
	riskScoreTest := riskScoreFFsEnabled || riskScoreThreshold != -1

	forceLegacyTest := config.GetBool(ForceLegacyCLIEnvVar)
	// Legacy test fallthrough
	if forceLegacyTest || (!sbomReachabilityTest && !riskScoreTest && !reachability) {
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

	orgUUID, err := uuid.Parse(orgID)
	if err != nil {
		return nil, fmt.Errorf("orgID is not a valid UUID: %w", err)
	}

	if reachability {
		sc := setupSettingsClient(ictx)
		//nolint:govet // Shadowing err is not an issue here.
		isReachEnabled, err := sc.IsReachabilityEnabled(ctx, orgUUID)
		if err != nil {
			return nil, fmt.Errorf("failed to check reachability settings: %w", err)
		}

		if !isReachEnabled {
			return nil, ecosystems.NewReachabilitySettingDisabledError(
				"In order to run the `test` command with `--reachability`, the reachability settings must be enabled.",
			)
		}
	}

	if riskScoreThreshold != -1 && !riskScoreFFsEnabled {
		// The user tried to use a risk score threshold without the required feature flags.
		// Return a specific error for the first missing flag found.
		if !ffRiskScore {
			return nil, errFactory.NewFeatureNotPermittedError(FeatureFlagRiskScore)
		}
		return nil, errFactory.NewFeatureNotPermittedError(FeatureFlagRiskScoreInCLI)
	}

	localPolicy := CreateLocalPolicy(config, logger)

	testClient, err := setupTestClient(ictx)
	if err != nil {
		return nil, err
	}

	// Route to the appropriate flow based on flags
	switch {
	case sbomReachabilityTest:
		return handleSBOMReachabilityFlow(ctx, ictx, testClient, orgID, sbom, sourceDir, errFactory, logger, localPolicy)
	case reachability:
		return handleDepgraphReachabilityFlow(ctx, ictx, testClient, orgUUID, sourceDir, errFactory, logger, localPolicy)
	default:
		return RunUnifiedTestFlow(ctx, ictx, testClient, orgID, errFactory, logger, localPolicy, nil)
	}
}
