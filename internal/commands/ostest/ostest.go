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
	"bytes"
	"context"
	"encoding/json"
	std_errors "errors"
	"fmt"
	"math"
	"os"
	"sort"
	"time"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/code_workflow"
	"github.com/snyk/go-application-framework/pkg/local_workflows/config_utils"
	"github.com/snyk/go-application-framework/pkg/local_workflows/content_type"
	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"
	"github.com/snyk/go-application-framework/pkg/workflow"

	service "github.com/snyk/cli-extension-os-flows/internal/common"
	"github.com/snyk/cli-extension-os-flows/internal/errors"
	"github.com/snyk/cli-extension-os-flows/internal/flags"
	"github.com/snyk/cli-extension-os-flows/internal/legacy/definitions"
	"github.com/snyk/cli-extension-os-flows/internal/legacy/transform"
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

// ApplicationJSONContentType matches the content type for legacy JSON findings records.
const ApplicationJSONContentType = "application/json"

// LogFieldCount is the logger key for number of findings.
const LogFieldCount = "count"

// ErrNoSummaryData is returned when a test summary cannot be generated due to lack of data.
var ErrNoSummaryData = std_errors.New("no summary data to create")

// PollInterval is the polling interval for the test API. It is exported to be configurable in tests.
var PollInterval = 8 * time.Second

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
		if config.GetBool(ForceLegacyCLIEnvVar) {
			logger.Debug().Msgf("Using legacy flow due to %s environment variable.", ForceLegacyCLIEnvVar)
			return code_workflow.EntryPointLegacy(ictx)
		}

		ffRiskScore := config.GetBool(FeatureFlagRiskScore)
		ffRiskScoreInCLI := config.GetBool(FeatureFlagRiskScoreInCLI)
		useUnifiedFlow := ffRiskScore && ffRiskScoreInCLI

		// The unified test flow is only used if both risk score feature flags are enabled.
		riskScoreThreshold := config.GetInt(flags.FlagRiskScoreThreshold)
		if riskScoreThreshold != -1 && !useUnifiedFlow {
			// The user tried to use a risk score threshold without the required feature flags.
			// Return a specific error for the first missing flag found.
			if !ffRiskScore {
				return nil, errFactory.NewFeatureNotPermittedError(FeatureFlagRiskScore)
			}
			return nil, errFactory.NewFeatureNotPermittedError(FeatureFlagRiskScoreInCLI)
		}

		if !useUnifiedFlow {
			logger.Debug().Msg("Using legacy flow since one or both experimental risk score feature flags are not enabled.")
			return code_workflow.EntryPointLegacy(ictx)
		}

		// Unified test flow
		orgID := config.GetString(configuration.ORGANIZATION)
		if orgID == "" {
			logger.Error().Msg("No organization ID provided")
			return nil, errFactory.NewEmptyOrgError()
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

		return runUnifiedTestFlow(ctx, riskScorePtr, severityThresholdPtr, ictx, config, orgID, errFactory, logger)
	}
}

// Create local policy only if risk score or severity threshold are specified.
func createLocalPolicy(riskScoreThreshold *uint16, severityThreshold *testapi.Severity) *testapi.LocalPolicy {
	if riskScoreThreshold == nil && severityThreshold == nil {
		return nil
	}

	localPolicy := &testapi.LocalPolicy{}
	if riskScoreThreshold != nil {
		localPolicy.RiskScoreThreshold = riskScoreThreshold
	}
	if severityThreshold != nil {
		localPolicy.SeverityThreshold = severityThreshold
	}
	return localPolicy
}

// runUnifiedTestFlow handles the unified test API flow.
func runUnifiedTestFlow(
	ctx context.Context,
	riskScoreThreshold *uint16,
	severityThreshold *testapi.Severity,
	ictx workflow.InvocationContext,
	_ configuration.Configuration,
	orgID string,
	errFactory *errors.ErrorFactory,
	logger *zerolog.Logger,
) ([]workflow.Data, error) {
	logger.Info().Msg("Starting open source test")

	// Create depgraphs and get their associated target files
	depGraphs, displayTargetFiles, err := createDepGraphs(ictx)
	if err != nil {
		return nil, err
	}
	var allFindings []definitions.LegacyVulnerabilityResponse
	var allSummaries []workflow.Data

	localPolicy := createLocalPolicy(riskScoreThreshold, severityThreshold)

	for i, depGraph := range depGraphs {
		displayTargetFile := ""
		if i < len(displayTargetFiles) {
			displayTargetFile = displayTargetFiles[i]
		}

		// Create depgraph subject
		depGraphSubject := testapi.DepGraphSubjectCreate{
			Type:     testapi.DepGraphSubjectCreateTypeDepGraph,
			DepGraph: depGraph,
			Locator: testapi.LocalPathLocator{
				Paths: []string{displayTargetFile},
				Type:  testapi.LocalPath,
			},
		}

		// Create test subject with depgraph
		var subject testapi.TestSubjectCreate
		err = subject.FromDepGraphSubjectCreate(depGraphSubject)
		if err != nil {
			return nil, fmt.Errorf("failed to create test subject: %w", err)
		}

		// Project name assigned as follows: --project-name || config project name || scannedProject?.depTree?.name
		// TODO: use project name from Config file
		config := ictx.GetConfiguration()
		projectName := config.GetString(flags.FlagProjectName)
		if projectName == "" && len(depGraph.Pkgs) > 0 {
			projectName = depGraph.Pkgs[0].Info.Name
		}

		packageManager := depGraph.PkgManager.Name
		depCount := max(0, len(depGraph.Pkgs)-1)

		// Run the test with the depgraph subject
		findings, summary, err := runTest(ctx, subject, projectName, packageManager, depCount, displayTargetFile, ictx, orgID, errFactory, logger, localPolicy)
		if err != nil {
			return nil, err
		}

		if findings != nil {
			allFindings = append(allFindings, *findings)
		}
		if summary != nil {
			allSummaries = append(allSummaries, summary)
		}
	}

	var finalOutput []workflow.Data
	if len(allFindings) > 0 {
		var findingsData any
		if len(allFindings) == 1 {
			findingsData = allFindings[0]
		} else {
			findingsData = allFindings
		}

		var buffer bytes.Buffer
		encoder := json.NewEncoder(&buffer)
		encoder.SetEscapeHTML(false)
		encoder.SetIndent("", "  ")
		err := encoder.Encode(findingsData)
		if err != nil {
			return nil, errFactory.NewLegacyJSONTransformerError(fmt.Errorf("marshaling to json: %w", err))
		}
		// encoder.Encode adds a newline, which we trim to match Marshal's behavior.
		findingsBytes := bytes.TrimRight(buffer.Bytes(), "\n")

		finalOutput = append(finalOutput, NewWorkflowData(ApplicationJSONContentType, findingsBytes))
	}

	finalOutput = append(finalOutput, allSummaries...)

	return finalOutput, nil
}

// runTest executes the common test flow with the provided test subject.
func runTest(
	ctx context.Context,
	subject testapi.TestSubjectCreate,
	projectName string,
	packageManager string,
	depCount int,
	displayTargetFile string,
	ictx workflow.InvocationContext,
	orgID string,
	errFactory *errors.ErrorFactory,
	logger *zerolog.Logger,
	localPolicy *testapi.LocalPolicy,
) (*definitions.LegacyVulnerabilityResponse, workflow.Data, error) {
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
		testapi.WithPollInterval(PollInterval),
		testapi.WithCustomHTTPClient(snykClient.GetClient()),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create test client: %w", err)
	}

	handle, err := testClient.StartTest(ctx, startParams)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to start test: %w", err)
	}

	if waitErr := handle.Wait(ctx); waitErr != nil {
		return nil, nil, fmt.Errorf("test run failed: %w", waitErr)
	}

	finalResult := handle.Result()
	if finalResult == nil {
		return nil, nil, fmt.Errorf("test completed but no result was returned")
	}

	// Get findings for the test
	findingsData, complete, err := finalResult.Findings(ctx)
	if err != nil {
		logger.Error().Err(err).Msg("Error fetching findings")
		if !complete && len(findingsData) > 0 {
			logger.Warn().Int(LogFieldCount, len(findingsData)).Msg("Partial findings retrieved as an error occurred")
		}
	} else {
		logger.Info().Msgf("Findings count: %d\n", len(findingsData))

		logger.Info().
			Bool("complete", complete).
			Int(LogFieldCount, len(findingsData)).
			Msg("Findings fetched successfully")
	}

	// path should be the current working directory
	currentDir, err := os.Getwd()
	if err != nil {
		logger.Error().Err(err).Msg("Failed to get current working directory")
		return nil, nil, fmt.Errorf("failed to get current working directory: %w", err)
	}

	var uniqueCount int32
	summary := finalResult.GetEffectiveSummary()
	if summary != nil {
		if summary.Count > math.MaxInt32 {
			uniqueCount = math.MaxInt32
			logger.Warn().Uint32(LogFieldCount, summary.Count).Msg("Unique finding count exceeds int32 max, capping value.")
		} else {
			uniqueCount = int32(summary.Count)
		}
	}

	legacyVulnResponse, err := transform.ConvertSnykSchemaFindingsToLegacy(
		&transform.SnykSchemaToLegacyParams{
			Findings:          findingsData,
			TestResult:        finalResult,
			ProjectName:       projectName,
			PackageManager:    packageManager,
			CurrentDir:        currentDir,
			UniqueCount:       uniqueCount,
			DepCount:          depCount,
			DisplayTargetFile: displayTargetFile,
			ErrFactory:        errFactory,
			Logger:            logger,
		})
	if err != nil {
		return nil, nil, fmt.Errorf("error converting snyk schema findings to legacy json: %w", err)
	}

	summaryData, err := NewSummaryData(finalResult, logger, currentDir)
	if err != nil {
		if !std_errors.Is(err, ErrNoSummaryData) {
			logger.Warn().Err(err).Msg("Failed to create test summary for exit code handling")
		}
		return legacyVulnResponse, nil, nil
	}

	return legacyVulnResponse, summaryData, nil
}

// extractSeverityKeys returns a map of severity keys present in the summaries.
func extractSeverityKeys(summaries ...*testapi.FindingSummary) map[string]bool {
	keys := make(map[string]bool)
	for _, summary := range summaries {
		if summary != nil && summary.CountBy != nil {
			if severityCounts, ok := (*summary.CountBy)["severity"]; ok {
				for severity := range severityCounts {
					keys[severity] = true
				}
			}
		}
	}
	return keys
}

// getSeverityCount safely retrieves the count for a given severity from a summary.
func getSeverityCount(summary *testapi.FindingSummary, severity string) uint32 {
	if summary == nil || summary.CountBy == nil {
		return 0
	}
	if severityCounts, ok := (*summary.CountBy)["severity"]; ok {
		return severityCounts[severity]
	}
	return 0
}

// NewSummaryData creates a workflow.Data object containing a json_schemas.TestSummary
// from a testapi.TestResult. This is used for downstream processing, like determining
// the CLI exit code.
func NewSummaryData(testResult testapi.TestResult, logger *zerolog.Logger, path string) (workflow.Data, error) {
	rawSummary := testResult.GetRawSummary()
	effectiveSummary := testResult.GetEffectiveSummary()

	if rawSummary == nil || effectiveSummary == nil {
		return nil, fmt.Errorf("test result missing summary information")
	}

	if rawSummary.Count == 0 {
		logger.Debug().Msg("No findings in summary, skipping summary creation.")
		return nil, fmt.Errorf("no findings in summary: %w", ErrNoSummaryData)
	}

	severityKeys := extractSeverityKeys(rawSummary, effectiveSummary)

	var summaryResults []json_schemas.TestSummaryResult
	for severity := range severityKeys {
		total := getSeverityCount(rawSummary, severity)
		open := getSeverityCount(effectiveSummary, severity)

		if total > 0 || open > 0 {
			ignored := 0
			if total > open {
				ignored = int(total - open)
			}
			summaryResults = append(summaryResults, json_schemas.TestSummaryResult{
				Severity: severity,
				Total:    int(total),
				Open:     int(open),
				Ignored:  ignored,
			})
		}
	}

	if len(summaryResults) > 0 {
		// Sort results for consistent output, matching the standard CLI order.
		sort.Slice(summaryResults, func(i, j int) bool {
			order := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}
			return order[summaryResults[i].Severity] > order[summaryResults[j].Severity]
		})

		testSummary := json_schemas.NewTestSummary("open-source", path)
		testSummary.Results = summaryResults
		testSummary.SeverityOrderAsc = []string{"low", "medium", "high", "critical"}

		summaryBytes, err := json.Marshal(testSummary)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal test summary: %w", err)
		}

		summaryWorkflowData := NewWorkflowData(content_type.TEST_SUMMARY, summaryBytes)
		return summaryWorkflowData, nil
	}

	return nil, fmt.Errorf("no summary results to process: %w", ErrNoSummaryData)
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

// createDepGraphs creates depgraphs from the file parameter in the context.
func createDepGraphs(ictx workflow.InvocationContext) ([]testapi.IoSnykApiV1testdepgraphRequestDepGraph, []string, error) {
	depGraphResult, err := service.GetDepGraph(ictx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get dependency graph: %w", err)
	}

	if len(depGraphResult.DepGraphBytes) == 0 {
		return nil, nil, fmt.Errorf("no dependency graphs found")
	}

	depGraphs := make([]testapi.IoSnykApiV1testdepgraphRequestDepGraph, len(depGraphResult.DepGraphBytes))
	for i, depGraphBytes := range depGraphResult.DepGraphBytes {
		var depGraphStruct testapi.IoSnykApiV1testdepgraphRequestDepGraph
		err = json.Unmarshal(depGraphBytes, &depGraphStruct)
		if err != nil {
			return nil, nil,
				fmt.Errorf("unmarshaling depGraph from args failed: %w", err)
		}
		depGraphs[i] = depGraphStruct
	}

	return depGraphs, depGraphResult.DisplayTargetFiles, nil
}

// NewWorkflowData creates a workflow.Data object with the given content type and data.
func NewWorkflowData(contentType string, data []byte) workflow.Data {
	return workflow.NewData(
		workflow.NewTypeIdentifier(WorkflowID, "ostest"),
		contentType,
		data,
	)
}
