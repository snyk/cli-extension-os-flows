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
	"os"
	"time"

	"github.com/google/uuid"
	codeclient "github.com/snyk/code-client-go"
	codeclienthttp "github.com/snyk/code-client-go/http"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/code_workflow"
	"github.com/snyk/go-application-framework/pkg/local_workflows/config_utils"
	"github.com/snyk/go-application-framework/pkg/ui"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-os-flows/internal/bundlestore"
	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	cmdutil "github.com/snyk/cli-extension-os-flows/internal/commands/util"
	"github.com/snyk/cli-extension-os-flows/internal/constants"
	"github.com/snyk/cli-extension-os-flows/internal/errors"
	"github.com/snyk/cli-extension-os-flows/internal/flags"
	"github.com/snyk/cli-extension-os-flows/internal/instrumentation"
	"github.com/snyk/cli-extension-os-flows/internal/legacy/definitions"
	"github.com/snyk/cli-extension-os-flows/internal/legacy/transform"
	"github.com/snyk/cli-extension-os-flows/internal/settings"
	"github.com/snyk/cli-extension-os-flows/internal/snykclient"
	"github.com/snyk/cli-extension-os-flows/internal/util"
)

// WorkflowID is the identifier for the Open Source Test workflow.
var WorkflowID = workflow.NewWorkflowIdentifier("test")

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
	config_utils.AddFeatureFlagToConfig(e, constants.FeatureFlagReachabilityForCLI, "reachabilityForCli")
	config_utils.AddFeatureFlagToConfig(e, constants.FeatureFlagSBOMTestReachability, "sbomTestReachability")

	// Risk score FFs.
	config_utils.AddFeatureFlagToConfig(e, constants.FeatureFlagRiskScore, "useExperimentalRiskScore")
	config_utils.AddFeatureFlagToConfig(e, constants.FeatureFlagRiskScoreInCLI, "useExperimentalRiskScoreInCLI")

	return nil
}

func setupTestClient(ctx context.Context) (testapi.TestClient, error) {
	cfg := cmdctx.Config(ctx)
	ictx := cmdctx.Ictx(ctx)
	httpClient := ictx.GetNetworkAccess().GetHttpClient()
	snykClient := snykclient.NewSnykClient(httpClient, cfg.GetString(configuration.API_URL), cfg.GetString(configuration.ORGANIZATION))

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

func setupSettingsClient(ctx context.Context) settings.Client {
	ictx := cmdctx.Ictx(ctx)
	cfg := cmdctx.Config(ctx)
	sc := settings.NewClient(ictx.GetNetworkAccess().GetHttpClient(), settings.Config{BaseURL: cfg.GetString(configuration.API_URL)})

	return sc
}

func setupBundlestoreClient(ctx context.Context) bundlestore.Client {
	ictx := cmdctx.Ictx(ctx)
	cfg := cmdctx.Config(ctx)
	logger := cmdctx.Logger(ctx)
	httpCodeClient := codeclienthttp.NewHTTPClient(
		ictx.GetNetworkAccess().GetHttpClient,
		codeclienthttp.WithLogger(logger),
	)

	codeScannerConfig := bundlestore.CodeClientConfig{
		LocalConfiguration: cfg,
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
	testClient testapi.TestClient,
	orgID, sbom, sourceDir string,
	localPolicy *testapi.LocalPolicy,
) ([]definitions.LegacyVulnerabilityResponse, []workflow.Data, error) {
	bsClient := setupBundlestoreClient(ctx)
	return RunSbomReachabilityFlow(ctx, testClient, sbom, sourceDir, bsClient, orgID, localPolicy)
}

func convertReachabilityFilterToSchema(reachabilityFilter string) *testapi.ReachabilityFilter {
	if reachabilityFilter == "" {
		return nil
	}

	switch reachabilityFilter {
	case "not-applicable", "not applicable":
		return util.Ptr(testapi.ReachabilityFilterNoInfo)
	case "no-path-found", "no path found":
		return util.Ptr(testapi.ReachabilityFilterNoPathFound)
	case "reachable":
		return util.Ptr(testapi.ReachabilityFilterReachable)
	default:
		return nil
	}
}

func getRiskScoreThreshold(ctx context.Context) *uint16 {
	cfg := cmdctx.Config(ctx)
	logger := cmdctx.Logger(ctx)
	riskScoreThresholdInt := cfg.GetInt(flags.FlagRiskScoreThreshold)
	if riskScoreThresholdInt >= math.MaxUint16 {
		// the API will enforce a range from the test spec
		logger.Warn().Msgf("Risk score threshold %d exceeds maximum uint16 value. Setting to maximum.", riskScoreThresholdInt)
		maxVal := uint16(math.MaxUint16)
		return &maxVal
	} else if riskScoreThresholdInt >= 0 {
		rs := uint16(riskScoreThresholdInt)
		return &rs
	}
	return nil
}

func getSeverityThreshold(ctx context.Context) *testapi.Severity {
	cfg := cmdctx.Config(ctx)
	severityThresholdStr := cfg.GetString(flags.FlagSeverityThreshold)
	if severityThresholdStr != "" {
		st := testapi.Severity(severityThresholdStr)
		return &st
	}
	return nil
}

func getReachabilityFilter(ctx context.Context) *testapi.ReachabilityFilter {
	cfg := cmdctx.Config(ctx)
	reachabilityFiltersFromConfig := convertReachabilityFilterToSchema(cfg.GetString(flags.FlagReachabilityFilter))

	if reachabilityFiltersFromConfig != nil {
		return reachabilityFiltersFromConfig
	}

	return nil
}

type supportedFailOnPolicy struct {
	onUpgradable *bool
}

func getFailOnPolicy(ctx context.Context) (supportedFailOnPolicy, error) {
	cfg := cmdctx.Config(ctx)
	errFactory := cmdctx.ErrorFactory(ctx)
	failOnFromConfig := cfg.GetString(flags.FlagFailOn)

	var failOnPolicy supportedFailOnPolicy
	if failOnFromConfig == "" {
		return failOnPolicy, nil
	}

	switch failOnFromConfig {
	case "upgradable", "all":
		failOnPolicy.onUpgradable = util.Ptr(true)
	default:
		return failOnPolicy, errFactory.NewUnsupportedFailOnValueError(failOnFromConfig)
	}

	return failOnPolicy, nil
}

func getLocalIgnores(ctx context.Context, inputDir string) (*[]testapi.LocalIgnore, error) {
	policy, err := cmdutil.GetLocalPolicy(ctx, inputDir)
	if err != nil {
		return nil, fmt.Errorf("failed to get local ignores: %w", err)
	}
	if policy != nil {
		return transform.LocalPolicyToSchema(policy), nil
	}
	//nolint:nilnil // Intentionally returning nil ignores if no policy is present.
	return nil, nil
}

// CreateLocalPolicy will create a local policy only if risk score or severity threshold or reachability filters are specified in the config.
func CreateLocalPolicy(cmdCtx context.Context, inputDir string) (*testapi.LocalPolicy, error) {
	riskScoreThreshold := getRiskScoreThreshold(cmdCtx)
	severityThreshold := getSeverityThreshold(cmdCtx)
	reachabilityFilter := getReachabilityFilter(cmdCtx)
	failOnPolicy, err := getFailOnPolicy(cmdCtx)
	if err != nil {
		return nil, err
	}
	localIgnores, err := getLocalIgnores(cmdCtx, inputDir)
	if err != nil {
		return nil, err
	}

	// if everything is nil, return nil for local policy (no error, just no policy)
	if riskScoreThreshold == nil && severityThreshold == nil && reachabilityFilter == nil && failOnPolicy.onUpgradable == nil && localIgnores == nil {
		var noPolicy *testapi.LocalPolicy
		return noPolicy, nil
	}

	// if we have some policy but no severity threshold, default to None
	if severityThreshold == nil {
		severityThreshold = util.Ptr(testapi.SeverityNone)
	}

	return &testapi.LocalPolicy{
		RiskScoreThreshold: riskScoreThreshold,
		SeverityThreshold:  severityThreshold,
		ReachabilityFilter: reachabilityFilter,
		FailOnUpgradable:   failOnPolicy.onUpgradable,
		Ignores:            localIgnores,
	}, nil
}

func getSourceDir(cfg configuration.Configuration, inputDir string) string {
	sourceDir := cfg.GetString(flags.FlagSourceDir)
	if sourceDir != "" {
		return sourceDir
	}

	return inputDir
}

func getInputDirectories(ctx context.Context) ([]string, error) {
	cfg := cmdctx.Config(ctx)
	sbom := cfg.GetString(flags.FlagSBOM)
	errFactory := cmdctx.ErrorFactory(ctx)

	inputDirs := cfg.GetStringSlice(configuration.INPUT_DIRECTORY)
	if len(inputDirs) > 1 && sbom != "" {
		//nolint:wrapcheck // No need to wrap error factory errors.
		return nil, errFactory.NewSBOMTestWithMultiplePathsError()
	}
	if len(inputDirs) == 0 {
		cwd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("failed to determine working directory: %w", err)
		}
		inputDirs = []string{cwd}
	}

	return inputDirs, nil
}

// OSWorkflow is the entry point for the Open Source Test workflow.
func OSWorkflow(
	ictx workflow.InvocationContext,
	_ []workflow.Data,
) ([]workflow.Data, error) {
	ctx := context.Background()
	cfg := ictx.GetConfiguration()
	logger := ictx.GetEnhancedLogger()
	errFactory := errors.NewErrorFactory(logger)
	progressBar := ictx.GetUserInterface().NewProgressBar()
	ctx = cmdctx.WithIctx(ctx, ictx)
	ctx = cmdctx.WithConfig(ctx, cfg)
	ctx = cmdctx.WithLogger(ctx, logger)
	ctx = cmdctx.WithErrorFactory(ctx, errFactory)
	ctx = cmdctx.WithProgressBar(ctx, progressBar)
	ctx = cmdctx.WithInstrumentation(ctx, instrumentation.NewGAFInstrumentation(ictx.GetAnalytics()))

	progressBar.SetTitle("Validating configuration...")
	//nolint:errcheck // We don't need to fail the command due to UI errors.
	progressBar.UpdateProgress(ui.InfiniteProgress)
	//nolint:errcheck // We don't need to fail the command due to UI errors.
	defer progressBar.Clear()

	flowCfg, err := ParseFlowConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to parse provided configuration: %w", err)
	}

	inputDirs, err := getInputDirectories(ctx)
	if err != nil {
		return nil, err
	}

	useLegacy, err := ShouldUseLegacyFlow(ctx, flowCfg, inputDirs)
	if err != nil {
		return nil, err
	}

	if useLegacy {
		//nolint:errcheck // We don't need to fail the command due to UI errors.
		progressBar.Clear()
		return code_workflow.EntryPointLegacy(ictx)
	}

	orgID := cfg.GetString(configuration.ORGANIZATION)
	if orgID == "" {
		logger.Error().Msg("No organization ID provided")
		return nil, errFactory.NewEmptyOrgError()
	}

	orgUUID, err := uuid.Parse(orgID)
	if err != nil {
		return nil, errFactory.NewInvalidOrgIDError(orgID)
	}

	// Determine which new flow to use
	sc := setupSettingsClient(ctx)
	flow, err := RouteToFlow(ctx, flowCfg, orgUUID, sc)
	if err != nil {
		return nil, err
	}

	sbom := cfg.GetString(flags.FlagSBOM)

	testClient, err := setupTestClient(ctx)
	if err != nil {
		return nil, err
	}

	allLegacyFindings := []definitions.LegacyVulnerabilityResponse{}
	allOutputData := []workflow.Data{}
	for _, inputDir := range inputDirs {
		// Reachability
		sourceDir := getSourceDir(cfg, inputDir)

		localPolicy, err := CreateLocalPolicy(ctx, inputDir)
		if err != nil {
			return nil, err
		}

		// Route to the appropriate flow based on flags
		var legacyFindings []definitions.LegacyVulnerabilityResponse
		var outputData []workflow.Data
		var flowErr error
		switch flow {
		case SBOMReachabilityFlow:
			legacyFindings, outputData, flowErr = handleSBOMReachabilityFlow(ctx, testClient, orgID, sbom, sourceDir, localPolicy)
		case DepgraphReachabilityFlow:
			legacyFindings, outputData, flowErr = RunUnifiedTestFlow(ctx, inputDir, testClient, orgUUID, localPolicy, &reachabilityOpts{sourceDir: sourceDir})
		case DepgraphFlow:
			legacyFindings, outputData, flowErr = RunUnifiedTestFlow(ctx, inputDir, testClient, orgUUID, localPolicy, nil)
		default:
			flowErr = fmt.Errorf("unknown test flow: %s", flow)
		}

		if flowErr != nil {
			return nil, flowErr
		}

		allLegacyFindings = append(allLegacyFindings, legacyFindings...)
		allOutputData = append(allOutputData, outputData...)
	}

	return handleOutput(ctx, allLegacyFindings, allOutputData)
}
