package ostest

import (
	"context"
	"encoding/json"
	std_errors "errors"
	"fmt"
	"math"
	"os"
	"sort"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/local_workflows/content_type"
	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-os-flows/internal/errors"
	"github.com/snyk/cli-extension-os-flows/internal/legacy/definitions"
	"github.com/snyk/cli-extension-os-flows/internal/legacy/transform"
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
) (*definitions.LegacyVulnerabilityResponse, workflow.Data, error) {
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

// NewWorkflowData creates a workflow.Data object with the given content type and data.
func NewWorkflowData(contentType string, data []byte) workflow.Data {
	return workflow.NewData(
		workflow.NewTypeIdentifier(WorkflowID, "ostest"),
		contentType,
		data,
	)
}
