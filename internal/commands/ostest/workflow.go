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
	"github.com/snyk/go-application-framework/pkg/apiclients/fileupload"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/config_utils"
	"github.com/snyk/go-application-framework/pkg/ui"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	cmdutil "github.com/snyk/cli-extension-os-flows/internal/commands/util"
	"github.com/snyk/cli-extension-os-flows/internal/constants"
	"github.com/snyk/cli-extension-os-flows/internal/deeproxy"
	"github.com/snyk/cli-extension-os-flows/internal/errors"
	"github.com/snyk/cli-extension-os-flows/internal/instrumentation"
	"github.com/snyk/cli-extension-os-flows/internal/legacy/definitions"
	"github.com/snyk/cli-extension-os-flows/internal/legacy/transform"
	"github.com/snyk/cli-extension-os-flows/internal/outputworkflow"
	"github.com/snyk/cli-extension-os-flows/internal/presenters"
	"github.com/snyk/cli-extension-os-flows/internal/reachability"
	"github.com/snyk/cli-extension-os-flows/internal/settings"
	"github.com/snyk/cli-extension-os-flows/internal/snykclient"
	"github.com/snyk/cli-extension-os-flows/internal/util"
	"github.com/snyk/cli-extension-os-flows/pkg/flags"
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

	// Risk score FFs.
	config_utils.AddFeatureFlagToConfig(e, constants.FeatureFlagRiskScore, "useExperimentalRiskScore")
	config_utils.AddFeatureFlagToConfig(e, constants.FeatureFlagRiskScoreInCLI, "useExperimentalRiskScoreInCLI")

	// Test shim FF for routing depgraph tests through the new test API.
	config_utils.AddFeatureFlagToConfig(e, constants.FeatureFlagUseTestShimForOSCliTest, "useTestShimForOSCliTest")

	// uv support FF.
	config_utils.AddFeatureFlagToConfig(e, constants.FeatureFlagUvCLI, "enableUvCLI")

	// SBOM support FF.
	config_utils.AddFeatureFlagsToConfig(e, map[string]string{
		constants.FeatureFlagShowMavenBuildScope: constants.ShowMavenBuildScope,
		constants.FeatureFlagShowNpmScope:        constants.ShowNpmScope,
	})

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

func setupFileUploadClient(ctx context.Context, orgID uuid.UUID) fileupload.Client {
	ictx := cmdctx.Ictx(ctx)
	cfg := cmdctx.Config(ctx)
	return fileupload.NewClient(
		ictx.GetNetworkAccess().GetHttpClient(),
		fileupload.Config{
			BaseURL: cfg.GetString(configuration.API_URL),
			OrgID:   orgID,
		},
		fileupload.WithLogger(ictx.GetEnhancedLogger()),
	)
}

func showEarlyAccessBanner(ictx workflow.InvocationContext) {
	cfg := ictx.GetConfiguration()

	if cfg.GetString(flags.FlagSBOM) == "" {
		return
	}
	if cfg.GetBool(outputworkflow.OutputConfigKeyJSON) {
		return
	}

	banner := presenters.RenderEarlyAccessBanner(presenters.SBOMEarlyAccessDocsURL)
	//nolint:errcheck // We don't need to fail the command due to UI errors.
	ictx.GetUserInterface().Output(banner)
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
		//nolint:wrapcheck // No need to wrap error factory errors.
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

// initializeWorkflowContext creates and configures the context for the workflow.
func initializeWorkflowContext(ictx workflow.InvocationContext) context.Context {
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

	return ctx
}

// validateAndParseOrgID validates the organization ID is present and parses it as a UUID.
func validateAndParseOrgID(ctx context.Context, orgID string) (uuid.UUID, error) {
	logger := cmdctx.Logger(ctx)
	errFactory := cmdctx.ErrorFactory(ctx)

	if orgID == "" {
		logger.Error().Msg("No organization ID provided")
		return uuid.UUID{}, errFactory.NewEmptyOrgError()
	}

	orgUUID, err := uuid.Parse(orgID)
	if err != nil {
		return uuid.UUID{}, errFactory.NewInvalidOrgIDError(orgID)
	}

	return orgUUID, nil
}

// ReachabilityOpts is used for passing reachability related
// setting in flows. If missing, then reachability is not requested.
type ReachabilityOpts struct {
	SourceDir string
}

// FlowClients is used for encapsulating all the clients needed
// for running the flows.
type FlowClients struct {
	TestClient         testapi.TestClient
	FileUploadClient   fileupload.Client
	ReachabilityClient reachability.Client
	DeeproxyClient     deeproxy.Client
}

// executeFlow runs the appropriate test flow based on the routing decision.
func executeFlow(
	ctx context.Context,
	flow Flow,
	clients FlowClients,
	orgUUID uuid.UUID,
	inputDir string,
	sourceDir string,
	sbom string,
	localPolicy *testapi.LocalPolicy,
	reachability bool,
) ([]definitions.LegacyVulnerabilityResponse, []workflow.Data, error) {
	var reachOpts *ReachabilityOpts
	if reachability {
		reachOpts = &ReachabilityOpts{SourceDir: sourceDir}
	}

	switch flow {
	case SbomFlow:
		return RunSbomFlow(ctx, clients, sbom, orgUUID, localPolicy, reachOpts)
	case DepgraphFlow:
		return RunUnifiedTestFlow(ctx, inputDir, clients, orgUUID, localPolicy, reachOpts)
	default:
		return nil, nil, fmt.Errorf("unknown test flow: %s", flow)
	}
}

// processInputDirectory handles testing a single input directory.
func processInputDirectory(
	ctx context.Context,
	clients FlowClients,
	inputDir string,
	orgUUID uuid.UUID,
	flow Flow,
	reachability bool,
	sbom string,
) ([]definitions.LegacyVulnerabilityResponse, []workflow.Data, error) {
	cfg := cmdctx.Config(ctx)
	errFactory := cmdctx.ErrorFactory(ctx)

	sourceDir := getSourceDir(cfg, inputDir)

	// Validate source directory exists when reachability is enabled
	if reachability {
		if err := ValidateSourceDir(sourceDir, errFactory); err != nil {
			return nil, nil, err
		}
	}

	localPolicy, err := CreateLocalPolicy(ctx, inputDir)
	if err != nil {
		return nil, nil, err
	}

	return executeFlow(ctx, flow, clients, orgUUID, inputDir, sourceDir, sbom, localPolicy, reachability)
}

// processAllInputDirectories iterates over all input directories and collects results.
func processAllInputDirectories(
	ctx context.Context,
	clients FlowClients,
	inputDirs []string,
	orgUUID uuid.UUID,
	flow Flow,
	reachability bool,
	sbom string,
) ([]definitions.LegacyVulnerabilityResponse, []workflow.Data, error) {
	allLegacyFindings := []definitions.LegacyVulnerabilityResponse{}
	allOutputData := []workflow.Data{}

	for _, inputDir := range inputDirs {
		legacyFindings, outputData, err := processInputDirectory(ctx, clients, inputDir, orgUUID, flow, reachability, sbom)
		if err != nil {
			return nil, nil, err
		}

		allLegacyFindings = append(allLegacyFindings, legacyFindings...)
		allOutputData = append(allOutputData, outputData...)
	}

	return allLegacyFindings, allOutputData, nil
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

func legacyEntrypoint(ctx context.Context) ([]workflow.Data, error) {
	ictx := cmdctx.Ictx(ctx)
	progressBar := cmdctx.ProgressBar(ctx)
	cfg := cmdctx.Config(ctx)
	logger := cmdctx.Logger(ctx)

	//nolint:errcheck // We don't need to fail the command due to UI errors.
	progressBar.Clear()

	legacyConfig := cfg.Clone()
	legacyArgs := cfg.GetStringSlice(configuration.RAW_CMD_ARGS)
	if len(legacyArgs) == 0 {
		legacyArgs = os.Args[1:]
	}
	legacyConfig.Set(configuration.RAW_CMD_ARGS, legacyArgs)
	legacyConfig.Set(configuration.WORKFLOW_USE_STDIO, true)

	logger.Debug().Strs("legacy_args", legacyArgs).Msg("legacy scan: RAW_CMD_ARGS passed to legacy CLI")

	//nolint:wrapcheck // No need to wrap legacy errors.
	return ictx.GetEngine().InvokeWithConfig(workflow.NewWorkflowIdentifier("legacycli"), legacyConfig)
}

// OSWorkflow is the entry point for the Open Source Test workflow.
func OSWorkflow(
	ictx workflow.InvocationContext,
	_ []workflow.Data,
) ([]workflow.Data, error) {
	showEarlyAccessBanner(ictx)

	ctx := initializeWorkflowContext(ictx)
	cfg := cmdctx.Config(ctx)
	progressBar := cmdctx.ProgressBar(ctx)

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

	// Get the showMavenBuildScope & showNpmBuildScope flags values & set in instrumentation
	inst := cmdctx.Instrumentation(ctx)
	inst.RecordShowMavenBuildScopeFlag(cfg.GetBool(constants.FeatureFlagShowMavenBuildScope))
	inst.RecordShowNpmScopeFlag(cfg.GetBool(constants.FeatureFlagShowNpmScope))

	useLegacy, err := ShouldUseLegacyFlow(ctx, flowCfg, inputDirs)
	if err != nil {
		return nil, err
	}
	if useLegacy {
		return legacyEntrypoint(ctx)
	}

	orgUUID, err := validateAndParseOrgID(ctx, cfg.GetString(configuration.ORGANIZATION))
	if err != nil {
		return nil, err
	}

	flow, err := RouteToFlow(ctx, flowCfg, orgUUID, setupSettingsClient(ctx))
	if err != nil {
		return nil, err
	}

	testClient, err := setupTestClient(ctx)
	if err != nil {
		return nil, err
	}
	fileUploadClient := setupFileUploadClient(ctx, orgUUID)
	reachabilityClient := reachability.NewClient(ictx.GetNetworkAccess().GetHttpClient(), reachability.Config{
		BaseURL: cfg.GetString(configuration.API_URL),
	})
	deeproxyClient := deeproxy.NewHTTPClient(deeproxy.Config{
		BaseURL:   cfg.GetString(configuration.API_URL),
		IsFedRamp: cfg.GetBool(configuration.IS_FEDRAMP),
	})

	allLegacyFindings, allOutputData, err := processAllInputDirectories(
		ctx,
		FlowClients{
			TestClient:         testClient,
			FileUploadClient:   fileUploadClient,
			ReachabilityClient: reachabilityClient,
			DeeproxyClient:     deeproxyClient,
		},
		inputDirs,
		orgUUID,
		flow,
		flowCfg.Reachability,
		flowCfg.SBOM,
	)
	if err != nil {
		return nil, err
	}

	//nolint:errcheck // We don't need to fail the command due to UI errors.
	progressBar.Clear()
	return handleOutput(ctx, allLegacyFindings, allOutputData)
}
