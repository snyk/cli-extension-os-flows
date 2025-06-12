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
	"encoding/json"
	"fmt"
	"math"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/code_workflow"
	"github.com/snyk/go-application-framework/pkg/local_workflows/config_utils"
	"github.com/snyk/go-application-framework/pkg/workflow"

	service "github.com/snyk/cli-extension-os-flows/internal/common"
	"github.com/snyk/cli-extension-os-flows/internal/errors"
	"github.com/snyk/cli-extension-os-flows/internal/flags"
	"github.com/snyk/cli-extension-os-flows/internal/snykclient"
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
		} else if riskScoreThreshold >= 0 {
			rs := uint16(riskScoreThreshold)
			riskScorePtr = &rs
		}
		return runUnifiedTestFlow(ctx, filename, riskScorePtr, ictx, config, orgID, logger)
	}
}

// runUnifiedTestFlow handles the unified test API flow.
func runUnifiedTestFlow(
	ctx context.Context,
	filename string,
	riskScoreThreshold *uint16,
	ictx workflow.InvocationContext,
	_ configuration.Configuration,
	orgID string,
	logger *zerolog.Logger,
) ([]workflow.Data, error) {
	logger.Info().Msg("Starting open source test")

	// Create depgraph
	depGraph, err := createDepGraph(ictx)
	if err != nil {
		return nil, fmt.Errorf("failed to create depgraph: %w", err)
	}

	// Create depgraph subject
	depGraphSubject := testapi.DepGraphSubjectCreate{
		Type:     testapi.DepGraphSubjectCreateTypeDepGraph,
		DepGraph: depGraph,
		Locator: testapi.LocalPathLocator{
			Paths: []string{filename},
			Type:  testapi.LocalPath,
		},
	}

	// Create test subject with depgraph
	var subject testapi.TestSubjectCreate
	err = subject.FromDepGraphSubjectCreate(depGraphSubject)
	if err != nil {
		return nil, fmt.Errorf("failed to create test subject: %w", err)
	}

	// Only create local policy if risk score threshold is specified
	var localPolicy *testapi.LocalPolicy
	if riskScoreThreshold != nil {
		localPolicy = &testapi.LocalPolicy{
			RiskScoreThreshold: riskScoreThreshold,
		}
	}

	// Run the test with the depgraph subject
	return runTest(ctx, subject, ictx, orgID, logger, localPolicy)
}

// runTest executes the common test flow with the provided test subject.
func runTest(
	ctx context.Context,
	subject testapi.TestSubjectCreate,
	ictx workflow.InvocationContext,
	orgID string,
	logger *zerolog.Logger,
	localPolicy *testapi.LocalPolicy,
) ([]workflow.Data, error) {
	// Create Snyk client
	httpClient := ictx.GetNetworkAccess().GetHttpClient()
	snykClient := snykclient.NewSnykClient(httpClient, ictx.GetConfiguration().GetString(configuration.API_URL), orgID)

	startParams := testapi.StartTestParams{
		OrgID:       orgID,
		Subject:     subject,
		LocalPolicy: localPolicy,
	}

	// Create and execute test client
	testClient, err := testapi.NewTestClient(
		snykClient.GetAPIBaseURL(),
		testapi.WithCustomHTTPClient(snykClient.GetClient()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create test client: %w", err)
	}

	handle, err := testClient.StartTest(ctx, startParams)
	if err != nil {
		return nil, fmt.Errorf("failed to start test: %w", err)
	}

	if waitErr := handle.Wait(ctx); waitErr != nil {
		return nil, fmt.Errorf("test run failed: %w", err)
	}

	finalStatus := handle.Result()
	if finalStatus == nil {
		return nil, fmt.Errorf("test completed but no result was returned")
	}

	// Process and log the test results
	processTestResult(finalStatus)

	// Get findings for the test
	findingsData, complete, err := finalStatus.Findings(ctx)
	if err != nil {
		logger.Error().Err(err).Msg("Error fetching findings")
		if !complete && len(findingsData) > 0 {
			logger.Warn().Int("count", len(findingsData)).Msg("Partial findings retrieved as an error occurred")
		}
	} else {
		logger.Info().Msgf("Findings count: %d\n", len(findingsData))

		logger.Info().
			Bool("complete", complete).
			Int("count", len(findingsData)).
			Msg("Findings fetched successfully")
	}

	// Convert findings to workflow data
	findingsJSON, err := json.Marshal(findingsData)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to marshal findings to JSON")
		return nil, fmt.Errorf("failed to marshal findings: %w", err)
	}

	return []workflow.Data{newWorkflowData(nil, "application/json", findingsJSON)}, nil
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

// createDepGraph creates a depgraph from the file parameter in the context.
func createDepGraph(ictx workflow.InvocationContext) (testapi.IoSnykApiV1testdepgraphRequestDepGraph, error) {
	var contents []byte
	var err error

	depGraphResult, err := service.GetDepGraph(ictx)
	if err != nil {
		return testapi.IoSnykApiV1testdepgraphRequestDepGraph{}, fmt.Errorf("failed to get dependency graph: %w", err)
	}

	if len(depGraphResult.DepGraphBytes) > 1 {
		err = fmt.Errorf("multiple depgraphs found, but only one is currently supported")
		return testapi.IoSnykApiV1testdepgraphRequestDepGraph{}, err
	}
	// TODO revisit handling multiple depgraphs
	contents = depGraphResult.DepGraphBytes[0]

	var depGraphStruct testapi.IoSnykApiV1testdepgraphRequestDepGraph
	err = json.Unmarshal(contents, &depGraphStruct)
	if err != nil {
		return testapi.IoSnykApiV1testdepgraphRequestDepGraph{},
			fmt.Errorf("unmarshaling depGraph from args failed: %w", err)
	}

	return depGraphStruct, nil
}

// Temporary support for dumping findings output to built-in JSON formatter.
func newWorkflowData(depGraph workflow.Data, contentType string, sbom []byte) workflow.Data {
	// TODO: refactor to workflow.NewData()
	//nolint:staticcheck // Silencing since we are only upgrading the GAF to remediate a vuln.
	return workflow.NewDataFromInput(
		depGraph,
		workflow.NewTypeIdentifier(WorkflowID, "ostest"),
		contentType,
		sbom,
	)
}
