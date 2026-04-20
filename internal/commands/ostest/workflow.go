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
	"os"

	"github.com/google/uuid"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/config_utils"
	"github.com/snyk/go-application-framework/pkg/ui"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-os-flows/internal/commands/clientsetup"
	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	"github.com/snyk/cli-extension-os-flows/internal/common"
	"github.com/snyk/cli-extension-os-flows/internal/constants"
	"github.com/snyk/cli-extension-os-flows/internal/errors"
	"github.com/snyk/cli-extension-os-flows/internal/instrumentation"
	"github.com/snyk/cli-extension-os-flows/internal/legacy/definitions"
	"github.com/snyk/cli-extension-os-flows/internal/legacy/validation"
	"github.com/snyk/cli-extension-os-flows/internal/outputworkflow"
	"github.com/snyk/cli-extension-os-flows/internal/presenters"
	"github.com/snyk/cli-extension-os-flows/pkg/flags"
)

// WorkflowID is the identifier for the Open Source Test workflow.
var WorkflowID = workflow.NewWorkflowIdentifier("test")

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

	// Dragonfly rollout.
	config_utils.AddFeatureFlagsToConfig(e, map[string]string{
		constants.FeatureFlagDlfyCLIRollout: "rollout-dfly-os-cli",
	})

	// SBOM support FF.
	config_utils.AddFeatureFlagsToConfig(e, map[string]string{
		constants.FeatureFlagShowMavenBuildScope: constants.ShowMavenBuildScope,
		constants.FeatureFlagShowNpmScope:        constants.ShowNpmScope,
	})

	return nil
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

// executeFlow runs the appropriate test flow based on the routing decision.
func executeFlow(
	ctx context.Context,
	flow Flow,
	clients common.FlowClients,
	orgUUID uuid.UUID,
	inputDir string,
	sourceDir string,
	sbom string,
	localPolicy *testapi.LocalPolicy,
	reachability bool,
) ([]definitions.LegacyVulnerabilityResponse, []workflow.Data, error) {
	var reachOpts *common.ReachabilityOpts
	if reachability {
		reachOpts = &common.ReachabilityOpts{SourceDir: sourceDir}
	}

	switch flow {
	case SbomFlow:
		return RunSbomFlow(ctx, clients, sbom, orgUUID, localPolicy, reachOpts)
	case DflyDepgraphFlow:
		dgResolver := common.NewDepgraphResolver()
		findings, data, err := common.RunDflyDepgraphFlow(ctx, inputDir, dgResolver, clients, orgUUID, localPolicy, reachOpts, nil, RunTestWithResources)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to run depgraph flow: %w", err)
		}
		return findings, data, nil
	case DepgraphFlow:
		return RunUnifiedTestFlow(ctx, inputDir, clients, orgUUID, localPolicy, reachOpts)
	default:
		return nil, nil, fmt.Errorf("unknown test flow: %s", flow)
	}
}

// processInputDirectory handles testing a single input directory.
func processInputDirectory(
	ctx context.Context,
	clients common.FlowClients,
	inputDir string,
	orgUUID uuid.UUID,
	flow Flow,
	reachability bool,
	sbom string,
) ([]definitions.LegacyVulnerabilityResponse, []workflow.Data, error) {
	cfg := cmdctx.Config(ctx)
	errFactory := cmdctx.ErrorFactory(ctx)

	sourceDir := common.GetSourceDir(cfg, inputDir)

	if reachability {
		if err := common.ValidateSourceDir(sourceDir, errFactory); err != nil {
			return nil, nil, fmt.Errorf("failed to validate source directory: %w", err)
		}
	}

	localPolicy, err := common.CreateLocalPolicy(ctx, inputDir)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create local policy: %w", err)
	}

	return executeFlow(ctx, flow, clients, orgUUID, inputDir, sourceDir, sbom, localPolicy, reachability)
}

// processAllInputDirectories iterates over all input directories and collects results.
func processAllInputDirectories(
	ctx context.Context,
	clients common.FlowClients,
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

	//nolint:wrapcheck // Validation errors are coming from the error catalog.
	if err := validation.ValidateFlagValues(cfg, validation.CommandTest); err != nil {
		return nil, err
	}

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

	orgUUID, err := common.ValidateAndParseOrgID(ctx, cfg.GetString(configuration.ORGANIZATION))
	if err != nil {
		return nil, fmt.Errorf("failed to validate org ID: %w", err)
	}

	flow, err := RouteToFlow(ctx, flowCfg, orgUUID, clientsetup.SetupSettingsClient(ctx))
	if err != nil {
		return nil, err
	}

	testClient, err := clientsetup.SetupTestClient(ctx, common.PollInterval)
	if err != nil {
		return nil, fmt.Errorf("failed to set up test client: %w", err)
	}
	fileUploadClient := clientsetup.SetupFileUploadClient(ctx, orgUUID)
	reachabilityClient := clientsetup.SetupReachabilityClient(ctx)
	deeproxyClient := clientsetup.SetupDeeproxyClient(ctx)

	allLegacyFindings, allOutputData, err := processAllInputDirectories(
		ctx,
		common.FlowClients{
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
