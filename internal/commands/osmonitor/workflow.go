package osmonitor

import (
	"context"
	"fmt"
	"os"

	"github.com/google/uuid"
	codeclient "github.com/snyk/code-client-go"
	codeclienthttp "github.com/snyk/code-client-go/http"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/config_utils"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-os-flows/internal/bundlestore"
	"github.com/snyk/cli-extension-os-flows/internal/errors"
	"github.com/snyk/cli-extension-os-flows/internal/flags"
	"github.com/snyk/cli-extension-os-flows/internal/reachability"
)

// WorkflowID is the identifier for the Open Source Monitor workflow.
var WorkflowID = workflow.NewWorkflowIdentifier("monitor")

// FeatureFlagReachabilityForCLI is used to gate the legacy monitor reachability feature.
const FeatureFlagReachabilityForCLI = "feature_flag_monitor_reachability"

// RegisterWorkflows registers the "monitor" workflow.
func RegisterWorkflows(e workflow.Engine) error {
	// Check if workflow already exists
	if _, ok := e.GetWorkflow(WorkflowID); ok {
		return fmt.Errorf("workflow with ID %s already exists", WorkflowID)
	}

	c := workflow.ConfigurationOptionsFromFlagset(flags.OSMonitorFlagSet())

	if _, err := e.Register(WorkflowID, c, OSWorkflow); err != nil {
		return fmt.Errorf("error while registering test workflow: %w", err)
	}

	// Reachability FF.
	config_utils.AddFeatureFlagToConfig(e, FeatureFlagReachabilityForCLI, "reachabilityForCli")

	return nil
}

// GetReachabilityID will upload the source code directory, kick off a reachability scan, wait for the scan to complete and return the scan ID.
func GetReachabilityID(ctx context.Context, ictx workflow.InvocationContext, bsClient bundlestore.Client, rc reachability.Client) (reachability.ID, error) {
	cfg := ictx.GetConfiguration()

	sourceDir := cfg.GetString(flags.FlagSourceDir)
	if sourceDir == "" {
		sourceDir = "."
	}

	orgID, err := uuid.Parse(cfg.GetString(configuration.ORGANIZATION))
	if err != nil {
		return uuid.Nil, fmt.Errorf("orgID is invalid: %w", err)
	}

	hash, err := bsClient.UploadSourceCode(ctx, sourceDir)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to upload source code: %w", err)
	}

	scanID, err := rc.StartReachabilityAnalysis(ctx, orgID, hash)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to start reachability analysis: %w", err)
	}

	err = rc.WaitForReachabilityAnalysis(ctx, orgID, scanID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed waiting for reachability analysis results: %w", err)
	}

	return scanID, nil
}

// OSWorkflow is the entry point for the Open Source Monitor workflow.
func OSWorkflow(
	ictx workflow.InvocationContext,
	_ []workflow.Data,
) ([]workflow.Data, error) {
	ctx := context.Background()
	cfg := ictx.GetConfiguration()
	logger := ictx.GetEnhancedLogger()
	errFactory := errors.NewErrorFactory(logger)
	legacyArgs := os.Args[1:]

	if cfg.GetBool(flags.FlagReachability) {
		logger.Debug().Msg("Running analysis of source code")

		ffReachabilityInCLI := cfg.GetBool(FeatureFlagReachabilityForCLI)
		if !ffReachabilityInCLI {
			return nil, errFactory.NewFeatureNotPermittedError(FeatureFlagReachabilityForCLI)
		}

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

		sec := reachability.NewClient(ictx.GetNetworkAccess().GetHttpClient(), reachability.Config{
			BaseURL: cfg.GetString(configuration.API_URL),
		})

		scanID, err := GetReachabilityID(ctx, ictx, bsClient, sec)
		if err != nil {
			return nil, fmt.Errorf("failed to analyise source code: %w", err)
		}

		cfg.Set(flags.FlagReachabilityID, scanID)
		legacyArgs = append(legacyArgs, fmt.Sprintf("--reachability-id=%s", scanID))
	}

	engine := ictx.GetEngine()
	cfg.Set(configuration.WORKFLOW_USE_STDIO, true)
	cfg.Set(configuration.RAW_CMD_ARGS, legacyArgs)
	//nolint:wrapcheck // No need to wrap the error since the legacy CLI will be invoked.
	return engine.InvokeWithConfig(workflow.NewWorkflowIdentifier("legacycli"), cfg)
}
