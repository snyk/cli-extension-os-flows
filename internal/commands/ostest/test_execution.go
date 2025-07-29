package ostest

import (
	"context"
	"encoding/json"
	std_errors "errors"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/local_workflows/content_type"
	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-os-flows/internal/errors"
	"github.com/snyk/cli-extension-os-flows/internal/legacy/definitions"
	"github.com/snyk/cli-extension-os-flows/internal/legacy/transform"
	"github.com/snyk/cli-extension-os-flows/internal/outputworkflow"
	"github.com/snyk/cli-extension-os-flows/internal/presenters"
)

// ApplicationJSONContentType matches the content type for legacy JSON findings records.
const ApplicationJSONContentType = "application/json"

// LogFieldCount is the logger key for number of findings.
const LogFieldCount = "count"

// ErrNoSummaryData is returned when a test summary cannot be generated due to lack of data.
var ErrNoSummaryData = std_errors.New("no summary data to create")

// RunTest executes the common test flow with the provided test subject.
func RunTest(
	ctx context.Context,
	ictx workflow.InvocationContext,
	testClient testapi.TestClient,
	subject testapi.TestSubjectCreate,
	projectName string,
	packageManager string,
	depCount int,
	displayTargetFile string,
	orgID string,
	errFactory *errors.ErrorFactory,
	logger *zerolog.Logger,
	localPolicy *testapi.LocalPolicy,
) (*definitions.LegacyVulnerabilityResponse, []workflow.Data, error) {
	finalResult, findingsData, err := executeTest(ctx, testClient, orgID, subject, localPolicy, errFactory, logger)
	if err != nil {
		return nil, nil, err
	}

	// path should be the current working directory
	currentDir, wdErr := os.Getwd()
	if wdErr != nil {
		logger.Error().Err(wdErr).Msg("Failed to get current working directory")
		return nil, nil, fmt.Errorf("failed to get current working directory: %w", wdErr)
	}

	uniqueCount := calculateUniqueIssueCount(findingsData)

	// The summary is always needed for the exit code calculation.
	standardSummary, summaryData, summaryErr := NewSummaryData(finalResult, logger, currentDir)
	if summaryErr != nil && !std_errors.Is(summaryErr, ErrNoSummaryData) {
		// Log the error but continue, as this is not fatal.
		logger.Warn().Err(summaryErr).Msg("Failed to create test summary for exit code handling")
	}

	legacyParams := &transform.SnykSchemaToLegacyParams{
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
	}

	return prepareOutput(ictx, findingsData, standardSummary, summaryData, legacyParams)
}

// executeTest runs the test and returns the results.
func executeTest(
	ctx context.Context,
	testClient testapi.TestClient,
	orgID string,
	subject testapi.TestSubjectCreate,
	localPolicy *testapi.LocalPolicy,
	errFactory *errors.ErrorFactory,
	logger *zerolog.Logger,
) (testapi.TestResult, []testapi.FindingData, error) {
	startParams := testapi.StartTestParams{
		OrgID:       orgID,
		Subject:     subject,
		LocalPolicy: localPolicy,
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

	if finalResult.GetExecutionState() == testapi.Errored {
		apiErrors := finalResult.GetErrors()
		if apiErrors != nil && len(*apiErrors) > 0 {
			var errorMessages []string
			for _, apiError := range *apiErrors {
				errorMessages = append(errorMessages, apiError.Detail)
			}
			return nil, nil, errFactory.NewTestExecutionError(strings.Join(errorMessages, "; "))
		}
		return nil, nil, errFactory.NewTestExecutionError("an unknown error occurred")
	}

	// Get findings for the test
	findingsData, complete, err := finalResult.Findings(ctx)
	if err != nil {
		logger.Error().Err(err).Msg("Error fetching findings")
		if !complete && len(findingsData) > 0 {
			logger.Warn().Int(LogFieldCount, len(findingsData)).Msg("Partial findings retrieved as an error occurred")
		}
	}
	return finalResult, findingsData, nil
}

// prepareOutput prepares the workflow data for output.
func prepareOutput(
	ictx workflow.InvocationContext,
	findingsData []testapi.FindingData,
	standardSummary *json_schemas.TestSummary,
	summaryData workflow.Data,
	params *transform.SnykSchemaToLegacyParams,
) (*definitions.LegacyVulnerabilityResponse, []workflow.Data, error) {
	config := ictx.GetConfiguration()
	var outputData []workflow.Data
	if summaryData != nil {
		outputData = append(outputData, summaryData)
	}

	wantsJSONStdOut := config.GetBool("json")
	jsonFileOutput := config.GetString(outputworkflow.OutputConfigKeyJSONFile)
	wantsJSONFile := jsonFileOutput != ""
	wantsAnyJSON := wantsJSONStdOut || wantsJSONFile
	var legacyVulnResponse *definitions.LegacyVulnerabilityResponse

	// Prepare legacy JSON response if any JSON output is requested.
	if wantsAnyJSON {
		var err error
		legacyVulnResponse, err = transform.ConvertSnykSchemaFindingsToLegacy(params)
		if err != nil {
			return nil, nil, fmt.Errorf("error converting snyk schema findings to legacy json: %w", err)
		}
	}

	// Prepare human-readable output unless JSON is being printed to stdout.
	if !wantsJSONStdOut {
		// For human-readable output, we pass the raw findings and summary to the output workflow.
		findingsBytes, err := json.Marshal(findingsData)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal findings: %w", err)
		}
		outputData = append(outputData, NewWorkflowData("application/json; schema=local-unified-finding", findingsBytes))

		if standardSummary != nil {
			extendedPayload := presenters.SummaryPayload{
				Summary:           standardSummary,
				DependencyCount:   params.DepCount,
				PackageManager:    params.PackageManager,
				ProjectName:       params.ProjectName,
				DisplayTargetFile: params.DisplayTargetFile,
				UniqueCount:       params.UniqueCount,
			}

			extendedPayloadBytes, marshalErr := json.Marshal(extendedPayload)
			if marshalErr != nil {
				return nil, nil, fmt.Errorf("failed to marshal extended summary payload: %w", marshalErr)
			}
			outputData = append(outputData, NewWorkflowData("application/json; schema=local-unified-summary", extendedPayloadBytes))
		}
	}
	return legacyVulnResponse, outputData, nil
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

// NewSummaryData creates a workflow.Data object containing a json_schemas.TestSummary
// from a testapi.TestResult. This is used for downstream processing, like determining
// the CLI exit code.
func NewSummaryData(testResult testapi.TestResult, logger *zerolog.Logger, path string) (*json_schemas.TestSummary, workflow.Data, error) {
	rawSummary := testResult.GetRawSummary()
	effectiveSummary := testResult.GetEffectiveSummary()

	if rawSummary == nil || effectiveSummary == nil {
		return nil, nil, fmt.Errorf("test result missing summary information")
	}

	if rawSummary.Count == 0 {
		logger.Debug().Msg("No findings in summary, skipping summary creation.")
		return nil, nil, fmt.Errorf("no findings in summary: %w", ErrNoSummaryData)
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
			return nil, nil, fmt.Errorf("failed to marshal test summary: %w", err)
		}

		summaryWorkflowData := NewWorkflowData(content_type.TEST_SUMMARY, summaryBytes)
		return testSummary, summaryWorkflowData, nil
	}

	return nil, nil, fmt.Errorf("no summary results to process: %w", ErrNoSummaryData)
}

// calculateUniqueIssueCount iterates through findings to determine the number of unique issues.
// A unique issue is identified by its Snyk ID (e.g., SNYK-JS-LODASH-12345).
func calculateUniqueIssueCount(findings []testapi.FindingData) int32 {
	issueIDs := make(map[string]bool)
	for _, finding := range findings {
		var snykID string
		// A finding can have multiple problems (e.g., a CVE and a Snyk ID).
		// We iterate through them to find the canonical Snyk ID for uniqueness.
		for _, problem := range finding.Attributes.Problems {
			var id string

			// The problem is a union type, so we need to check which type it is.
			if p, err := problem.AsSnykVulnProblem(); err == nil {
				id = p.Id
			} else if p, err := problem.AsSnykLicenseProblem(); err == nil {
				id = p.Id
			}

			if id != "" {
				snykID = id
				break // Found a Snyk ID, we can stop searching for this finding.
			}
		}

		if snykID != "" {
			issueIDs[snykID] = true
		}
	}

	count := len(issueIDs)
	if count > math.MaxInt32 {
		return math.MaxInt32
	}
	return int32(count)
}

// NewWorkflowData creates a workflow.Data object with the given content type and data.
func NewWorkflowData(contentType string, data []byte) workflow.Data {
	return workflow.NewData(
		workflow.NewTypeIdentifier(WorkflowID, "ostest"),
		contentType,
		data,
	)
}
