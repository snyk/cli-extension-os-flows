package ostest

import (
	"context"
	"encoding/json"
	std_errors "errors"
	"fmt"
	"sort"
	"strings"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
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

	config := ictx.GetConfiguration()
	targetDir := config.GetString(configuration.INPUT_DIRECTORY)

	orgSlugOrID := config.GetString(configuration.ORGANIZATION_SLUG)
	if orgSlugOrID == "" {
		logger.Info().Msg("No organization slug provided; using organization ID.")
		orgSlugOrID = orgID
	}

	allFindingsData := findingsData
	vulnerablePathsCount := calculateVulnerablePathsCount(allFindingsData)

	// Deep copy findings for consolidation to avoid modifying the original slice,
	// which would affect the JSON output.
	b, err := json.Marshal(allFindingsData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal findings for deep copy: %w", err)
	}
	var findingsForConsolidation []testapi.FindingData
	if err := json.Unmarshal(b, &findingsForConsolidation); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal findings for deep copy: %w", err)
	}

	consolidatedFindings := consolidateFindings(findingsForConsolidation, logger)
	//nolint:gosec // G115: integer overflow is not a concern here
	uniqueCount := int32(len(consolidatedFindings))

	// The summary is always needed for the exit code calculation.
	standardSummary, summaryData, summaryErr := NewSummaryDataFromFindings(consolidatedFindings, logger, targetDir)
	if summaryErr != nil {
		// Log other errors but continue, as this is not fatal.
		logger.Warn().Err(summaryErr).Msg("Failed to create test summary for exit code handling")
	}

	legacyParams := &transform.SnykSchemaToLegacyParams{
		Findings:          allFindingsData,
		TestResult:        finalResult,
		OrgSlugOrID:       orgSlugOrID,
		ProjectName:       projectName,
		PackageManager:    packageManager,
		TargetDir:         targetDir,
		UniqueCount:       uniqueCount,
		DepCount:          depCount,
		DisplayTargetFile: displayTargetFile,
		ErrFactory:        errFactory,
		Logger:            logger,
	}

	return prepareOutput(ictx, consolidatedFindings, standardSummary, summaryData, legacyParams, vulnerablePathsCount)
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
	vulnerablePathsCount int,
) (*definitions.LegacyVulnerabilityResponse, []workflow.Data, error) {
	config := ictx.GetConfiguration()
	var outputData []workflow.Data
	if summaryData != nil {
		outputData = append(outputData, summaryData)
	}

	wantsJSONStdOut := config.GetBool(outputworkflow.OutputConfigKeyJSON)
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
				Summary:              standardSummary,
				DependencyCount:      params.DepCount,
				PackageManager:       params.PackageManager,
				ProjectName:          params.ProjectName,
				DisplayTargetFile:    params.DisplayTargetFile,
				UniqueCount:          params.UniqueCount,
				VulnerablePathsCount: vulnerablePathsCount,
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

// NewSummaryDataFromFindings creates a workflow.Data object containing a json_schemas.TestSummary
// from a list of findings. This is used for downstream processing, like determining
// the CLI exit code.
func NewSummaryDataFromFindings(
	findings []testapi.FindingData,
	_ *zerolog.Logger,
	path string,
) (*json_schemas.TestSummary, workflow.Data, error) {
	if len(findings) == 0 {
		testSummary := json_schemas.NewTestSummary("open-source", path)
		testSummary.Results = []json_schemas.TestSummaryResult{}
		testSummary.SeverityOrderAsc = []string{"low", "medium", "high", "critical"}
		summaryBytes, err := json.Marshal(testSummary)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal empty test summary: %w", err)
		}
		return testSummary, NewWorkflowData(content_type.TEST_SUMMARY, summaryBytes), nil
	}

	severityCounts := make(map[string]int)
	for _, finding := range findings {
		if finding.Attributes == nil {
			continue
		}
		severity := string(finding.Attributes.Rating.Severity)
		severityCounts[severity]++
	}

	summaryResults := make([]json_schemas.TestSummaryResult, 0, len(severityCounts))
	for severity, count := range severityCounts {
		summaryResults = append(summaryResults, json_schemas.TestSummaryResult{
			Severity: severity,
			Total:    count,
			Open:     count, // For this summary, all found issues are considered open.
			Ignored:  0,
		})
	}

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

// consolidateFindings consolidates findings with the same Snyk ID into a single finding
// with all the evidence and locations from the original findings.
func consolidateFindings(findings []testapi.FindingData, logger *zerolog.Logger) []testapi.FindingData {
	consolidatedFindings := make(map[string]testapi.FindingData)
	var orderedKeys []string

	for _, finding := range findings {
		snykID := getSnykID(finding)
		if snykID == "" {
			// If a finding has no Snyk ID, treat it as unique.
			if finding.Id == nil {
				logger.Error().Msg("finding is missing an ID")
				continue
			}
			snykID = finding.Id.String()
		}

		if existingFinding, exists := consolidatedFindings[snykID]; !exists {
			consolidatedFindings[snykID] = finding
			orderedKeys = append(orderedKeys, snykID)
		} else {
			// Deep copy to avoid modifying the map's shared object directly
			newFinding := existingFinding
			if newFinding.Attributes == nil && finding.Attributes != nil {
				newFinding.Attributes = &testapi.FindingAttributes{}
			}

			if finding.Attributes != nil {
				newFinding.Attributes.Evidence = append(newFinding.Attributes.Evidence, finding.Attributes.Evidence...)
				newFinding.Attributes.Locations = append(newFinding.Attributes.Locations, finding.Attributes.Locations...)
			}
			consolidatedFindings[snykID] = newFinding
		}
	}

	result := make([]testapi.FindingData, len(orderedKeys))
	for i, key := range orderedKeys {
		result[i] = consolidatedFindings[key]
	}
	return result
}

// getSnykID extracts the canonical Snyk ID from a finding.
// TODO This needs to use attributes.Key.
func getSnykID(finding testapi.FindingData) string {
	if finding.Attributes == nil || len(finding.Attributes.Problems) == 0 {
		return ""
	}

	for _, problem := range finding.Attributes.Problems {
		var id string
		disc, err := problem.Discriminator()
		if err != nil {
			continue
		}

		if disc == string(testapi.SnykVuln) {
			if p, err := problem.AsSnykVulnProblem(); err == nil {
				id = p.Id
			}
		} else if disc == string(testapi.SnykLicense) {
			if p, err := problem.AsSnykLicenseProblem(); err == nil {
				id = p.Id
			}
		}

		if id != "" {
			return id
		}
	}
	return ""
}

func calculateVulnerablePathsCount(findings []testapi.FindingData) int {
	var count int
	for _, finding := range findings {
		if finding.Attributes == nil {
			continue
		}
		for _, evidence := range finding.Attributes.Evidence {
			if disc, err := evidence.Discriminator(); err == nil && disc == string(testapi.DependencyPath) {
				count++
			}
		}
	}
	return count
}

// NewWorkflowData creates a workflow.Data object with the given content type and data.
func NewWorkflowData(contentType string, data []byte) workflow.Data {
	return workflow.NewData(
		workflow.NewTypeIdentifier(WorkflowID, "ostest"),
		contentType,
		data,
	)
}
