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
	stderrors "errors"
	"fmt"
	"io/fs"
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
	"github.com/snyk/cli-extension-os-flows/internal/errors"
	"github.com/snyk/cli-extension-os-flows/internal/fileupload"
	"github.com/snyk/cli-extension-os-flows/internal/flags"
	"github.com/snyk/cli-extension-os-flows/internal/legacy/transform"
	"github.com/snyk/cli-extension-os-flows/internal/policy"
	"github.com/snyk/cli-extension-os-flows/internal/reachability"
	"github.com/snyk/cli-extension-os-flows/internal/settings"
	"github.com/snyk/cli-extension-os-flows/internal/snykclient"
	"github.com/snyk/cli-extension-os-flows/internal/util"
	"github.com/snyk/cli-extension-os-flows/pkg/localpolicy"
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
) ([]workflow.Data, error) {
	bsClient := setupBundlestoreClient(ctx)
	return RunSbomReachabilityFlow(ctx, testClient, sbom, sourceDir, bsClient, orgID, localPolicy)
}

func handleDepgraphReachabilityFlow(
	ctx context.Context,
	testClient testapi.TestClient,
	orgUUID uuid.UUID,
	sourceDir string,
	localPolicy *testapi.LocalPolicy,
) ([]workflow.Data, error) {
	ictx := cmdctx.Ictx(ctx)
	cfg := cmdctx.Config(ctx)
	progressBar := cmdctx.ProgressBar(ctx)

	fuClient := fileupload.NewClientFromInvocationContext(ictx, orgUUID)
	rc := reachability.NewClient(ictx.GetNetworkAccess().GetHttpClient(), reachability.Config{
		BaseURL: cfg.GetString(configuration.API_URL),
	})

	progressBar.SetTitle("Uploading source code...")
	scanID, err := reachability.GetReachabilityID(ctx, orgUUID, sourceDir, rc, fuClient)
	if err != nil {
		return nil, fmt.Errorf("failed to analyze source code: %w", err)
	}

	return RunUnifiedTestFlow(ctx, testClient, orgUUID.String(), localPolicy, &scanID)
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

func getLocalPolicyDir(ctx context.Context) string {
	cfg := cmdctx.Config(ctx)
	if dir := cfg.GetString(flags.FlagPolicyPath); dir != "" {
		return dir
	}
	if dir := cfg.GetString(configuration.INPUT_DIRECTORY); dir != "" {
		return dir
	}
	cwd, err := os.Getwd()
	if err != nil {
		return ""
	}
	return cwd
}

// getLocalIgnores attempts to resolve a .snyk file and read the ignore rules within it.
// Failing to resolve, open or read the file is not fatal and will result in no ignores
// to be applied.
func getLocalIgnores(ctx context.Context) *[]testapi.LocalIgnore {
	logger := cmdctx.Logger(ctx)

	policyFile, err := policy.Resolve(getLocalPolicyDir(ctx))
	if err != nil {
		var perr *fs.PathError
		if stderrors.As(err, &perr) {
			logger.Info().Msg("No .snyk file found.")
		} else {
			logger.Warn().Err(err).Msg("Failed to load .snyk file.")
		}
		return nil
	}

	var p localpolicy.Policy
	if err = localpolicy.Unmarshal(policyFile, &p); err != nil {
		logger.Error().Err(err).Msg("Failed to read .snyk file.")
		return nil
	}

	return transform.LocalPolicyToSchema(&p)
}

// CreateLocalPolicy will create a local policy only if risk score or severity threshold or reachability filters are specified in the config.
func CreateLocalPolicy(cmdCtx context.Context) (*testapi.LocalPolicy, error) {
	riskScoreThreshold := getRiskScoreThreshold(cmdCtx)
	severityThreshold := getSeverityThreshold(cmdCtx)
	reachabilityFilter := getReachabilityFilter(cmdCtx)
	failOnPolicy, err := getFailOnPolicy(cmdCtx)
	if err != nil {
		return nil, err
	}
	localIgnores := getLocalIgnores(cmdCtx)

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

	progressBar.SetTitle("Validating configuration...")
	//nolint:errcheck // We don't need to fail the command due to UI errors.
	progressBar.UpdateProgress(ui.InfiniteProgress)
	//nolint:errcheck // We don't need to fail the command due to UI errors.
	defer progressBar.Clear()

	logger.Info().Msg("Getting preferred organization ID")
	orgID := cfg.GetString(configuration.ORGANIZATION)
	if orgID == "" {
		logger.Error().Msg("No organization ID provided")
		return nil, errFactory.NewEmptyOrgError()
	}
	orgUUID, err := uuid.Parse(orgID)
	if err != nil {
		return nil, fmt.Errorf("orgID is not a valid UUID: %w", err)
	}

	sc := setupSettingsClient(ctx)
	flow, err := RouteToFlow(ctx, orgUUID, sc)
	if err != nil {
		return nil, err
	}

	// Legacy test fallthrough
	if flow == LegacyFlow {
		// clear the progress bar early as to not interfere with the legacy command
		//nolint:errcheck // We don't need to fail the command due to UI errors.
		progressBar.Clear()
		return code_workflow.EntryPointLegacy(ictx)
	}

	// Reachability
	sourceDir := cfg.GetString(flags.FlagSourceDir)
	if sourceDir == "" {
		sourceDir = cfg.GetString(configuration.INPUT_DIRECTORY)
	}
	if sourceDir == "" {
		sourceDir = "."
	}

	sbom := cfg.GetString(flags.FlagSBOM)

	localPolicy, err := CreateLocalPolicy(ctx)
	if err != nil {
		return nil, err
	}

	testClient, err := setupTestClient(ctx)
	if err != nil {
		return nil, err
	}

	// Route to the appropriate flow based on flags
	switch flow {
	case SBOMReachabilityFlow:
		return handleSBOMReachabilityFlow(ctx, testClient, orgID, sbom, sourceDir, localPolicy)
	case DepgraphReachabilityFlow:
		return handleDepgraphReachabilityFlow(ctx, testClient, orgUUID, sourceDir, localPolicy)
	case DepgraphFlow:
		return RunUnifiedTestFlow(ctx, testClient, orgID, localPolicy, nil)
	default:
		return nil, fmt.Errorf("unknown test flow: %s", flow)
	}
}
