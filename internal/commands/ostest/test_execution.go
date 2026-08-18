//nolint:revive // Interferes with inline types from testapi.
package ostest

import (
	"context"
	"encoding/json"
	std_errors "errors"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/content_type"
	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"
	"github.com/snyk/go-application-framework/pkg/utils/ufm"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	"github.com/snyk/cli-extension-os-flows/internal/legacy/definitions"
	"github.com/snyk/cli-extension-os-flows/internal/legacy/transform"
	"github.com/snyk/cli-extension-os-flows/internal/outputworkflow"
	"github.com/snyk/cli-extension-os-flows/internal/presenters"
	"github.com/snyk/cli-extension-os-flows/internal/remediation"
	"github.com/snyk/cli-extension-os-flows/internal/util"
	"github.com/snyk/cli-extension-os-flows/pkg/semver"
)

// ApplicationJSONContentType matches the content type for legacy JSON findings records.
const ApplicationJSONContentType = "application/json"

// LogFieldCount is the logger key for number of findings.
const LogFieldCount = "count"

// ErrNoSummaryData is returned when a test summary cannot be generated due to lack of data.
var ErrNoSummaryData = std_errors.New("no summary data to create")

// RunTestWithSubject executes the common test flow with the provided test subject.
// Returns legacy JSON and/or human-readable workflow data, depending on parameters.
func RunTestWithSubject(
	ctx context.Context,
	targetDir string,
	testClient testapi.TestClient,
	subject testapi.TestSubjectCreate,
	projectName string,
	packageManager string,
	depCount int,
	targetFile string,
	displayTargetFile string,
	orgID string,
	localPolicy *testapi.LocalPolicy,
) (*definitions.LegacyVulnerabilityResponse, []workflow.Data, error) {
	testConfig := testapi.TestConfiguration{LocalPolicy: localPolicy}
	startParams := testapi.NewStartTestParamsFromSubject(orgID, &subject, &testConfig)
	return runSingleTest(ctx, targetDir, testClient, startParams, projectName, packageManager, depCount, targetFile, displayTargetFile)
}

// RunTestWithResources executes the test flow with the provided test resources (for SBOM flows).
// Returns legacy JSON and/or human-readable workflow data, depending on parameters.
func RunTestWithResources(
	ctx context.Context,
	targetDir string,
	testClient testapi.TestClient,
	resources []testapi.TestResourceCreateItem,
	projectName string,
	packageManager string,
	depCount int,
	targetFile string,
	displayTargetFile string,
	orgID string,
	testConfig *testapi.TestConfiguration,
) (*definitions.LegacyVulnerabilityResponse, []workflow.Data, error) {
	startParams := testapi.NewStartTestParamsFromResources(orgID, &resources, testConfig)
	return runSingleTest(ctx, targetDir, testClient, startParams, projectName, packageManager, depCount, targetFile, displayTargetFile)
}

// RunTestWithResourcesByComponent executes the test flow with the provided test resources and
// reports one result per component covered by the test.
//
// A test run against an SBOM covers every component in that document but is reported by the
// test API as a single test, so the findings are split back out per component. This gives the
// same one-result-per-project reporting as `snyk test --all-projects`, where each dep graph is
// its own test. It falls back to a single result when the test API reports no components.
func RunTestWithResourcesByComponent(
	ctx context.Context,
	targetDir string,
	testClient testapi.TestClient,
	resources []testapi.TestResourceCreateItem,
	projectName string,
	packageManager string,
	depCount int,
	targetFile string,
	displayTargetFile string,
	orgID string,
	testConfig *testapi.TestConfiguration,
) ([]definitions.LegacyVulnerabilityResponse, []workflow.Data, error) {
	startParams := testapi.NewStartTestParamsFromResources(orgID, &resources, testConfig)
	return runTestInternal(ctx, targetDir, testClient, startParams, &testTarget{
		projectName:       projectName,
		packageManager:    packageManager,
		depCount:          depCount,
		targetFile:        targetFile,
		displayTargetFile: displayTargetFile,
	}, true)
}

// testTarget describes what a set of findings is reported against: one project for a dep
// graph test, or one component when an SBOM test's results are split by component.
type testTarget struct {
	findings          []testapi.FindingData
	projectID         *string
	projectName       string
	packageManager    string
	depCount          int
	targetFile        string
	displayTargetFile string
}

// runSingleTest runs a test and reports its findings as a single result.
func runSingleTest(
	ctx context.Context,
	targetDir string,
	testClient testapi.TestClient,
	startParams testapi.StartTestParams,
	projectName string,
	packageManager string,
	depCount int,
	targetFile string,
	displayTargetFile string,
) (*definitions.LegacyVulnerabilityResponse, []workflow.Data, error) {
	legacyResponses, outputData, err := runTestInternal(ctx, targetDir, testClient, startParams, &testTarget{
		projectName:       projectName,
		packageManager:    packageManager,
		depCount:          depCount,
		targetFile:        targetFile,
		displayTargetFile: displayTargetFile,
	}, false)
	if err != nil {
		return nil, nil, err
	}
	if len(legacyResponses) == 0 {
		return nil, outputData, nil
	}
	return &legacyResponses[0], outputData, nil
}

// runTestInternal is the shared implementation for RunTest, RunTestWithResources and
// RunTestWithResourcesByComponent.
func runTestInternal(
	ctx context.Context,
	targetDir string,
	testClient testapi.TestClient,
	startParams testapi.StartTestParams,
	base *testTarget,
	splitByComponent bool,
) ([]definitions.LegacyVulnerabilityResponse, []workflow.Data, error) {
	cfg := cmdctx.Config(ctx)
	logger := cmdctx.Logger(ctx)

	finalResult, findingsData, err := executeTest(ctx, testClient, startParams)
	if err != nil {
		return nil, nil, err
	}

	orgSlugOrID := cfg.GetString(configuration.ORGANIZATION_SLUG)
	if orgSlugOrID == "" {
		logger.Info().Msg("No organization slug provided; using organization ID.")
		orgSlugOrID = startParams.OrgID()
	}

	base.findings = findingsData

	base.projectID, err = getTestProjectID(finalResult)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract project ID: %w", err)
	}

	// Use dependency count from test facts if available, otherwise fall back to the provided depCount.
	if factDepCount := GetDependencyCountFromTestFacts(finalResult); factDepCount > 0 {
		base.depCount = factDepCount
	}

	targets := []testTarget{*base}
	var split []ComponentFindings
	if splitByComponent {
		split = SplitFindingsByComponent(finalResult, findingsData)
		logger.Debug().
			Int("component_count", len(split)).
			Strs("component_keys", componentKeys(split)).
			Msg("Splitting test results by component")
		if len(split) > 0 {
			targets = componentTargets(split, base)
		}
	}

	var legacyResponses []definitions.LegacyVulnerabilityResponse
	var outputData []workflow.Data
	for i := range targets {
		legacyResponse, targetOutput, targetErr := prepareTargetOutput(ctx, finalResult, &targets[i], targetDir, orgSlugOrID)
		if targetErr != nil {
			return nil, nil, targetErr
		}
		if legacyResponse != nil {
			legacyResponses = append(legacyResponses, *legacyResponse)
		}
		outputData = append(outputData, targetOutput...)
	}

	// Test results go last so that the findings and summary of each target stay adjacent,
	// which is what the output workflow pairs on.
	if testResultData := prepareTestResultData(ctx, finalResult, base, targetDir, split, targets); testResultData != nil {
		outputData = append(outputData, testResultData)
	}

	return legacyResponses, outputData, nil
}

// componentTargets turns per-component findings into reportable targets.
//
// The flow's own target file is kept, and the component key becomes the display target file
// so that each result is headed by the component it covers. This mirrors `--all-projects`,
// where every project shares the input directory and is distinguished by its target file.
func componentTargets(split []ComponentFindings, base *testTarget) []testTarget {
	targets := make([]testTarget, 0, len(split))
	for _, component := range split {
		target := *base
		target.findings = component.Findings

		if component.Key != "" {
			target.projectName = component.Key
			target.displayTargetFile = component.Key
		}

		if component.ProjectID != nil {
			target.projectID = util.Ptr(component.ProjectID.String())
		} else if len(split) > 1 {
			// The test-wide project is not any single component's project, so pointing
			// every component at it would be wrong.
			target.projectID = nil
		}

		// The test API only reports a dependency count for the test as a whole, so it is
		// only meaningful when that test covers a single component.
		if len(split) > 1 {
			target.depCount = 0
		}

		targets = append(targets, target)
	}
	return targets
}

// prepareTargetOutput builds the legacy JSON response and workflow data for a single target.
func prepareTargetOutput(
	ctx context.Context,
	result testapi.TestResult,
	target *testTarget,
	targetDir string,
	orgSlugOrID string,
) (*definitions.LegacyVulnerabilityResponse, []workflow.Data, error) {
	logger := cmdctx.Logger(ctx)
	errFactory := cmdctx.ErrorFactory(ctx)

	vulnerablePathsCount := calculateVulnerablePathsCount(target.findings)

	consolidatedFindings, err := ConsolidateFindings(ctx, target.findings)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to consolidate findings: %w", err)
	}

	// The summary is always needed for the exit code calculation.
	standardSummary, summaryData, summaryErr := NewSummaryDataFromFindings(consolidatedFindings, targetDir)
	if summaryErr != nil {
		// Log other errors but continue, as this is not fatal.
		logger.Warn().Err(summaryErr).Msg("Failed to create test summary for exit code handling")
	}

	remFindings, err := remediation.ShimFindingsToRemediationFindings(target.findings)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to convert to remediation findings: %w", err)
	}

	remSummary, err := remediation.FindingsToRemediationSummary(remFindings)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compute remediation summary: %w", err)
	}

	legacyParams := &transform.SnykSchemaToLegacyParams{
		Findings:           target.findings,
		ProjectID:          target.projectID,
		RemediationSummary: remSummary,
		TestResult:         result,
		OrgSlugOrID:        orgSlugOrID,
		ProjectName:        target.projectName,
		PackageManager:     target.packageManager,
		TargetDir:          targetDir,
		DepCount:           target.depCount,
		TargetFile:         target.targetFile,
		DisplayTargetFile:  target.displayTargetFile,
		ErrFactory:         errFactory,
		Logger:             logger,
	}

	return prepareOutput(ctx, consolidatedFindings, standardSummary, summaryData, legacyParams, vulnerablePathsCount)
}

func getTestProjectID(result testapi.TestResult) (*string, error) {
	locators, ok := result.Get(testapi.TestResultSubjectLocators).(*[]testapi.TestSubjectLocator)
	if !ok || locators == nil {
		//nolint:nilnil // Nil is a proper value to be returned, indicating a missing project id.
		return nil, nil
	}

	for _, loc := range *locators {
		disc, err := loc.Discriminator()
		if err != nil {
			return nil, fmt.Errorf("failed to get subject locator discriminator: %w", err)
		}
		if disc != string(testapi.ProjectEntity) {
			continue
		}
		peLoc, err := loc.AsProjectEntityLocator()
		if err != nil {
			return nil, fmt.Errorf("failed to convert subject locator to project entity locator: %w", err)
		}
		return util.Ptr(peLoc.ProjectId.String()), nil
	}

	//nolint:nilnil // Nil is a proper value to be returned, indicating a missing project id.
	return nil, nil
}

func assetLinkFromTestResult(result testapi.TestResult) string {
	if result == nil {
		return ""
	}
	v := result.GetMetadataValue("asset")
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// GetDependencyCountFromTestFacts extracts the total dependency count from test facts.
// Returns 0 if no dependency count fact is found.
func GetDependencyCountFromTestFacts(result testapi.TestResult) int {
	testFacts, ok := result.Get(testapi.TestResultTestFacts).(*[]testapi.TestFact)
	if !ok || testFacts == nil {
		return 0
	}

	for _, fact := range *testFacts {
		if fact.Type == testapi.DependencyCountFactTypeDependencyCountFact {
			return int(fact.TotalDependencyCount)
		}
	}

	return 0
}

// executeTest runs the test with the provided parameters and returns the results.
func executeTest(
	ctx context.Context,
	testClient testapi.TestClient,
	startParams testapi.StartTestParams,
) (testapi.TestResult, []testapi.FindingData, error) {
	logger := cmdctx.Logger(ctx)
	errFactory := cmdctx.ErrorFactory(ctx)
	progressbar := cmdctx.ProgressBar(ctx)

	progressbar.SetTitle("Starting test...")
	logStartTestParams(logger, startParams)
	handle, err := testClient.StartTest(ctx, startParams)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to start test: %w", err)
	}

	progressbar.SetTitle("Waiting for test completion...")
	if waitErr := handle.Wait(ctx); waitErr != nil {
		return nil, nil, fmt.Errorf("test run failed: %w", waitErr)
	}

	finalResult := handle.Result()
	if finalResult == nil {
		return nil, nil, fmt.Errorf("test completed but no result was returned")
	}

	if finalResult.GetExecutionState() == testapi.TestExecutionStatesErrored {
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
		return finalResult, findingsData, errFactory.NewTestExecutionError(
			fmt.Sprintf("test completed but findings could not be retrieved: %v", err),
		)
	}
	if !complete {
		if len(findingsData) > 0 {
			logger.Warn().Int(LogFieldCount, len(findingsData)).Msg("Partial findings retrieved; findings retrieval incomplete")
		}
		return finalResult, findingsData, errFactory.NewTestExecutionError("test completed but findings could not be retrieved")
	}
	return finalResult, findingsData, nil
}

// logStartTestParams emits a debug log describing the request that is about to be sent
// to the test-api shim: org ID, resource count, presence of a subject, and the most
// useful CLI-supplied metadata (asset_name, target_reference, project_business_criticality,
// project_environment, project_lifecycle, project_tags, publish_report). The full
// TestConfiguration is also emitted as JSON via RawJSON for completeness, but the
// individual fields are surfaced as top-level zerolog fields so they are immediately
// greppable and not subject to any JSON-targeted scrubbing rules.
func logStartTestParams(logger *zerolog.Logger, startParams testapi.StartTestParams) {
	dbg := logger.Debug()
	if !dbg.Enabled() {
		return
	}

	dbg = dbg.Str("org_id", startParams.OrgID())

	if resources := startParams.Resources(); resources != nil {
		dbg = dbg.Int("resource_count", len(*resources))
	} else {
		dbg = dbg.Int("resource_count", 0)
	}

	dbg = dbg.Bool("has_subject", startParams.Subject() != nil)

	if cfg := startParams.TestConfig(); cfg != nil {
		dbg = appendTestConfig(dbg, cfg)
	}

	dbg.Msg("Sending StartTest request to test-api shim")
}

// appendTestConfig adds the non-nil fields of cfg to the debug log event.
func appendTestConfig(dbg *zerolog.Event, cfg *testapi.TestConfiguration) *zerolog.Event {
	if cfg.AssetName != nil {
		dbg = dbg.Str("asset_name", *cfg.AssetName)
	}
	if cfg.TargetReference != nil {
		dbg = dbg.Str("target_reference", *cfg.TargetReference)
	}
	if cfg.ProjectBusinessCriticality != nil {
		dbg = dbg.Str("project_business_criticality", *cfg.ProjectBusinessCriticality)
	}
	if cfg.ProjectEnvironment != nil {
		dbg = dbg.Strs("project_environment", *cfg.ProjectEnvironment)
	}
	if cfg.ProjectLifecycle != nil {
		dbg = dbg.Strs("project_lifecycle", *cfg.ProjectLifecycle)
	}
	if cfg.ProjectTags != nil {
		dbg = dbg.Strs("project_tags", *cfg.ProjectTags)
	}
	if cfg.PublishReport != nil {
		dbg = dbg.Bool("publish_report", *cfg.PublishReport)
	}
	if cfgJSON, err := json.Marshal(cfg); err == nil {
		dbg = dbg.RawJSON("test_config", cfgJSON)
	} else {
		dbg = dbg.AnErr("test_config_marshal_err", err)
	}
	return dbg
}

// prepareTestResultData sets the metadata on the result and wraps the test and its results
// as workflow data.
//
// The unified findings presenter renders one section per test result, so when the findings
// were split by component each component is presented as its own test result. Otherwise the
// single underlying result is emitted as-is.
//
// Facts that describe the test as a whole, such as the asset it covers, are reported on the
// test rather than on its results. A component is not the thing the asset belongs to, and
// copying the same value onto each of them only has to be undone again when rendering.
func prepareTestResultData(
	ctx context.Context,
	result testapi.TestResult,
	base *testTarget,
	targetDir string,
	split []ComponentFindings,
	targets []testTarget,
) workflow.Data {
	ictx := cmdctx.Ictx(ctx)

	result.SetMetadata("package-manager", base.packageManager)
	result.SetMetadata("project-name", base.projectName)
	result.SetMetadata("display-target-file", base.displayTargetFile)
	result.SetMetadata("target-directory", targetDir)
	result.SetMetadata("dependency-count", base.depCount)

	testMetadata := splitTestWideMetadata(resultMetadata(result))

	results := []testapi.TestResult{result}
	if len(split) > 0 {
		results = componentTestResults(result, split, targets, targetDir)
	}

	return ufm.CreateWorkflowDataFromTest(ictx.GetWorkflowIdentifier(), testMetadata, results)
}

// prepareOutput prepares raw test result findings into data for the output workflow.
// If JSON is requested (either to file or stdout), it generates legacy JSON findings.
// If JSON-stdout is not requested, then human-readable findings are added to the output workflow.
// Human-readable stdout with JSON file output is a valid combination and returns both human-readable and legacy JSON types.
func prepareOutput(
	ctx context.Context,
	findingsData []testapi.FindingData,
	standardSummary *json_schemas.TestSummary,
	summaryData workflow.Data,
	params *transform.SnykSchemaToLegacyParams,
	vulnerablePathsCount int,
) (*definitions.LegacyVulnerabilityResponse, []workflow.Data, error) {
	cfg := cmdctx.Config(ctx)

	var outputData []workflow.Data
	if summaryData != nil {
		outputData = append(outputData, summaryData)
	}

	if cfg.GetBool(outputworkflow.OutputConfigKeyNoOutput) {
		return nil, outputData, nil
	}

	wantsJSONStdOut := cfg.GetBool(outputworkflow.OutputConfigKeyJSON)
	jsonFileOutput := cfg.GetString(outputworkflow.OutputConfigKeyJSONFile)
	wantsJSONFile := jsonFileOutput != ""
	wantsAnyJSON := wantsJSONStdOut || wantsJSONFile
	var legacyVulnResponse *definitions.LegacyVulnerabilityResponse

	// Prepare legacy JSON response if any JSON output is requested.
	if wantsAnyJSON {
		var err error
		legacyVulnResponse, err = transform.ConvertSnykSchemaFindingsToLegacy(ctx, params)
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
				TargetDirectory:      params.TargetDir,
				VulnerablePathsCount: vulnerablePathsCount,
				AssetLink:            assetLinkFromTestResult(params.TestResult),
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

type severityCount struct {
	total   int
	ignored int
}

// NewSummaryDataFromFindings creates a workflow.Data object containing a json_schemas.TestSummary
// from a list of findings. This is used for downstream processing, like determining
// the CLI exit code.
func NewSummaryDataFromFindings(
	findings []testapi.FindingData,
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

	severityCounts := make(map[string]severityCount)
	for _, finding := range findings {
		if finding.Attributes == nil {
			continue
		}

		severity := string(finding.Attributes.Rating.Severity)
		sevCount, ok := severityCounts[severity]
		if !ok {
			sevCount = severityCount{}
		}

		sevCount.total++
		if finding.Attributes.Suppression != nil &&
			finding.Attributes.Suppression.Status == testapi.SuppressionStatusIgnored {
			sevCount.ignored++
		}

		severityCounts[severity] = sevCount
	}

	summaryResults := make([]json_schemas.TestSummaryResult, 0, len(severityCounts))
	for severity, sevCount := range severityCounts {
		summaryResults = append(summaryResults, json_schemas.TestSummaryResult{
			Severity: severity,
			Total:    sevCount.total,
			Open:     sevCount.total - sevCount.ignored,
			Ignored:  sevCount.ignored,
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

// ConsolidateFindings consolidates findings with the same Snyk ID into a single finding
// with all the evidence, locations and fixes from the original findings.
// It preserves the highest risk score and severity rating.
func ConsolidateFindings(ctx context.Context, findings []testapi.FindingData) ([]testapi.FindingData, error) {
	logger := cmdctx.Logger(ctx)

	consolidatedFindings := make(map[string]testapi.FindingData)
	var orderedKeys []string

	// Severity order for comparison (higher index = higher severity)
	severityOrder := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}

	for _, finding := range findings {
		info, err := getIssueInfoFromFinding(finding)
		if err != nil {
			return nil, err
		}
		if info.ID == "" {
			// If a finding has no Snyk ID, treat it as unique.
			if finding.Id == nil {
				logger.Error().Msg("finding is missing an ID")
				continue
			}
			info.ID = finding.Id.String()
		}

		if existingFinding, exists := consolidatedFindings[info.ID]; !exists {
			consolidatedFindings[info.ID] = finding
			orderedKeys = append(orderedKeys, info.ID)
		} else {
			consolidatedFindingWithAttributes := consolidateFindingAttributes(existingFinding, finding, severityOrder)
			consolidatedFindingWithFix, err := consolidateFindingFix(consolidatedFindingWithAttributes, finding, info.PackageManager)
			if err != nil {
				return nil, fmt.Errorf("failed to consolidate finding fix: %w", err)
			}
			consolidatedFindings[info.ID] = *consolidatedFindingWithFix
		}
	}

	result := make([]testapi.FindingData, len(orderedKeys))
	for i, key := range orderedKeys {
		result[i] = consolidatedFindings[key]
	}
	return result, nil
}

func consolidateFindingFix(existing, additional testapi.FindingData, pkgManager string) (*testapi.FindingData, error) {
	if additional.Relationships == nil || additional.Relationships.Fix == nil {
		return &existing, nil
	}
	if existing.Relationships == nil {
		existing.Relationships = &struct {
			Asset *struct {
				Data *struct {
					Id   uuid.UUID "json:\"id\""
					Type string    "json:\"type\""
				} "json:\"data,omitempty\""
				Links testapi.IoSnykApiCommonRelatedLink "json:\"links\""
				Meta  *testapi.IoSnykApiCommonMeta       "json:\"meta,omitempty\""
			} "json:\"asset,omitempty\""
			Fix *struct {
				Data *struct {
					Attributes *testapi.FixAttributes "json:\"attributes,omitempty\""
					Id         uuid.UUID              "json:\"id\""
					Type       string                 "json:\"type\""
				} "json:\"data,omitempty\""
			} "json:\"fix,omitempty\""
			Org *struct {
				Data *struct {
					Id   uuid.UUID "json:\"id\""
					Type string    "json:\"type\""
				} "json:\"data,omitempty\""
			} "json:\"org,omitempty\""
			Policy *struct {
				Data *struct {
					// Attributes Inlined attributes included in the relationship, if it is expanded.
					//
					// Expansion is a Snyk variation on JSON API. See
					// https://snyk.roadie.so/docs/default/component/sweater-comb/standards/rest/#expansion
					Attributes *testapi.PolicyAttributes `json:"attributes,omitempty"`
					Id         uuid.UUID                 `json:"id"`
					Type       string                    `json:"type"`
				} `json:"data,omitempty"`
				Links testapi.IoSnykApiCommonRelatedLink `json:"links"`

				// Meta Free-form object that may contain non-standard information.
				Meta *testapi.IoSnykApiCommonMeta `json:"meta,omitempty"`
			} `json:"policy,omitempty"`
			Project *struct {
				Data *struct {
					Id   uuid.UUID "json:\"id\""
					Type string    "json:\"type\""
				} "json:\"data,omitempty\""
			} "json:\"project,omitempty\""
			Test *struct {
				Data *struct {
					Id   uuid.UUID "json:\"id\""
					Type string    "json:\"type\""
				} "json:\"data,omitempty\""
				Links testapi.IoSnykApiCommonRelatedLink "json:\"links\""
				Meta  *testapi.IoSnykApiCommonMeta       "json:\"meta,omitempty\""
			} "json:\"test,omitempty\""
		}{}
	}

	if existing.Relationships.Fix == nil {
		existing.Relationships.Fix = additional.Relationships.Fix
		return &existing, nil
	}

	existingAttrs := existing.Relationships.Fix.Data.Attributes
	additionalAttrs := additional.Relationships.Fix.Data.Attributes

	existingAttrs.Outcome = mergeUpgradeOutcome(existingAttrs.Outcome, additionalAttrs.Outcome)

	if existingAttrs.Action == nil {
		existingAttrs.Action = additionalAttrs.Action
		return &existing, nil
	}

	if additionalAttrs.Action == nil {
		return &existing, nil
	}

	action, err := mergeFixActions(existingAttrs.Action, additionalAttrs.Action, pkgManager)
	if err != nil {
		return nil, fmt.Errorf("failed to merge findings fix actions: %w", err)
	}
	existingAttrs.Action = action

	return &existing, nil
}

func mergeFixActions(a1, a2 *testapi.FixAction, pkgManager string) (*testapi.FixAction, error) {
	a1Type, err := a1.Discriminator()
	if err != nil {
		return nil, fmt.Errorf("failed to get action discriminator: %w", err)
	}

	a2Type, err := a2.Discriminator()
	if err != nil {
		return nil, fmt.Errorf("failed to get action discriminator: %w", err)
	}

	if a1Type != a2Type {
		return nil, fmt.Errorf("can not merge findings with different types: %s != %s", a1Type, a2Type)
	}

	switch a1Type {
	case string(testapi.UpgradePackageAdviceFormatUpgradePackageAdvice):
		a1UpgradeAction, err := a1.AsUpgradePackageAdvice()
		if err != nil {
			return nil, fmt.Errorf("failed to convert finding action to upgrade action: %w", err)
		}

		a2UpgradeAction, err := a2.AsUpgradePackageAdvice()
		if err != nil {
			return nil, fmt.Errorf("failed to convert finding action to upgrade action: %w", err)
		}

		a1UpgradeAction.UpgradePaths = append(a1UpgradeAction.UpgradePaths, a2UpgradeAction.UpgradePaths...)
		action := &testapi.FixAction{}
		err = action.FromUpgradePackageAdvice(a1UpgradeAction)
		if err != nil {
			return nil, fmt.Errorf("failed to convert upgrade action to finding action: %w", err)
		}
		return action, nil
	case string(testapi.PinPackageAdviceFormatPinPackageAdvice):
		a1PinAction, err := a1.AsPinPackageAdvice()
		if err != nil {
			return nil, fmt.Errorf("failed to convert finding action to pin action: %w", err)
		}

		a2PinAction, err := a2.AsPinPackageAdvice()
		if err != nil {
			return nil, fmt.Errorf("failed to convert finding action to pin action: %w", err)
		}

		maxVersion, err := getMaxVersion(pkgManager, a1PinAction.PinVersion, a2PinAction.PinVersion)
		if err != nil {
			return nil, fmt.Errorf("failed to determine maximum pin version: %w", err)
		}
		a1PinAction.PinVersion = maxVersion
		action := &testapi.FixAction{}
		err = action.FromPinPackageAdvice(a1PinAction)
		if err != nil {
			return nil, fmt.Errorf("failed to convert pin action to finding action: %w", err)
		}
		return action, nil
	default:
		return nil, fmt.Errorf("uknown action type: %s", a1Type)
	}
}

func mergeUpgradeOutcome(o1, o2 testapi.FixAppliedOutcome) testapi.FixAppliedOutcome {
	//nolint:gocritic // If-else is clearer than switch in this case.
	if o1 == testapi.FullyResolved && o2 == testapi.FullyResolved {
		return testapi.FullyResolved
	} else if o1 == testapi.Unresolved && o2 == testapi.Unresolved {
		return testapi.Unresolved
	} else {
		return testapi.PartiallyResolved
	}
}

// consolidateFindingAttributes consolidates attributes from two findings, preserving the highest risk score and severity.
func consolidateFindingAttributes(existing, additional testapi.FindingData, severityOrder map[string]int) testapi.FindingData {
	// deep copy the Attributes field to avoid modifying shared data
	result := existing
	if result.Attributes == nil && additional.Attributes != nil {
		result.Attributes = &testapi.FindingAttributes{}
	} else if result.Attributes != nil {
		result.Attributes = &testapi.FindingAttributes{
			CauseOfFailure: result.Attributes.CauseOfFailure,
			Description:    result.Attributes.Description,
			Evidence:       make([]testapi.Evidence, len(result.Attributes.Evidence)),
			FindingType:    result.Attributes.FindingType,
			Key:            result.Attributes.Key,
			Locations:      make([]testapi.FindingLocation, len(result.Attributes.Locations)),
			Problems:       make([]testapi.Problem, len(result.Attributes.Problems)),
			Rating:         result.Attributes.Rating,
			Risk:           result.Attributes.Risk,
			Suppression:    result.Attributes.Suppression,
			Title:          result.Attributes.Title,
		}
		// Copy slices
		copy(result.Attributes.Evidence, existing.Attributes.Evidence)
		copy(result.Attributes.Locations, existing.Attributes.Locations)
		copy(result.Attributes.Problems, existing.Attributes.Problems)

		// Deep copy PolicyModifications if it exists on existing
		if existing.Attributes != nil && existing.Attributes.PolicyModifications != nil {
			policyMods := make([]testapi.PolicyModification, len(*existing.Attributes.PolicyModifications))
			copy(policyMods, *existing.Attributes.PolicyModifications)
			result.Attributes.PolicyModifications = &policyMods
		}
	}

	if additional.Attributes != nil {
		result.Attributes.Evidence = append(result.Attributes.Evidence, additional.Attributes.Evidence...)
		result.Attributes.Locations = append(result.Attributes.Locations, additional.Attributes.Locations...)
		result.Attributes.Problems = append(result.Attributes.Problems, additional.Attributes.Problems...)

		// Consolidate PolicyModifications
		consolidatePolicyModifications(result.Attributes, additional.Attributes)

		// Preserve the highest risk score
		if additional.Attributes.Risk.RiskScore != nil {
			if result.Attributes.Risk.RiskScore == nil ||
				additional.Attributes.Risk.RiskScore.Value > result.Attributes.Risk.RiskScore.Value {
				result.Attributes.Risk.RiskScore = additional.Attributes.Risk.RiskScore
			}
		}

		// Preserve the highest severity rating
		currentSeverity := string(result.Attributes.Rating.Severity)
		newSeverity := string(additional.Attributes.Rating.Severity)
		if severityOrder[newSeverity] > severityOrder[currentSeverity] {
			result.Attributes.Rating.Severity = additional.Attributes.Rating.Severity
		}
	}
	return result
}

// consolidatePolicyModifications consolidates PolicyModifications from additional finding into result.
func consolidatePolicyModifications(result, additional *testapi.FindingAttributes) {
	if additional.PolicyModifications == nil {
		return
	}

	if result.PolicyModifications == nil {
		// Deep copy the additional PolicyModifications
		policyMods := make([]testapi.PolicyModification, len(*additional.PolicyModifications))
		copy(policyMods, *additional.PolicyModifications)
		result.PolicyModifications = &policyMods
	} else {
		// Append to existing PolicyModifications (already deep copied)
		*result.PolicyModifications = append(*result.PolicyModifications, *additional.PolicyModifications...)
	}
}

// getSnykID extracts the canonical Snyk ID from a finding.
func getMaxVersion(packageManager, v1, v2 string) (string, error) {
	semverResolver, err := semver.GetSemver(packageManager)
	if err != nil {
		return "", fmt.Errorf("failed to resolve semver library: %w", err)
	}
	var version string
	compare, err := semverResolver.Compare(v1, v2)
	if err != nil {
		return "", fmt.Errorf("failed to compare package versions: %w", err)
	}
	if compare >= 0 {
		version = v1
	} else {
		version = v2
	}
	return version, nil
}

type IssueInfo struct {
	ID             string
	PackageManager string
}

// getIssueInfoFromFinding extracts the canonical Snyk ID and it's package manager from a finding.
// TODO This needs to use attributes.Key.
func getIssueInfoFromFinding(finding testapi.FindingData) (IssueInfo, error) {
	if finding.Attributes == nil || len(finding.Attributes.Problems) == 0 {
		return IssueInfo{}, nil
	}

	for _, problem := range finding.Attributes.Problems {
		info, err := getIssueInfoFromProblem(problem)
		if err != nil {
			return IssueInfo{}, fmt.Errorf("failed to get issue info from problem: %w", err)
		}

		if info != nil {
			return *info, nil
		}
	}

	return IssueInfo{}, nil
}

func getIssueInfoFromProblem(p testapi.Problem) (*IssueInfo, error) {
	disc, err := p.Discriminator()
	if err != nil {
		return nil, fmt.Errorf("failed to get problem discriminator: %w", err)
	}

	switch disc {
	case string(testapi.SnykVuln):
		vuln, err := p.AsSnykVulnProblem()
		if err != nil {
			return nil, fmt.Errorf("failed to convert problem to snyk vuln: %w", err)
		}

		eco, err := vuln.Ecosystem.AsSnykvulndbBuildPackageEcosystem()
		if err != nil {
			return nil, fmt.Errorf("failed to convert ecosystem to build package ecosystem: %w", err)
		}

		return &IssueInfo{
			ID:             vuln.Id,
			PackageManager: eco.PackageManager,
		}, nil
	case string(testapi.SnykLicense):
		p, err := p.AsSnykLicenseProblem()
		if err != nil {
			return nil, fmt.Errorf("failed to convert problem to snyk license issue: %w", err)
		}

		eco, err := p.Ecosystem.AsSnykvulndbBuildPackageEcosystem()
		if err != nil {
			return nil, fmt.Errorf("failed to convert ecosystem to build package ecosystem: %w", err)
		}

		return &IssueInfo{
			ID:             p.Id,
			PackageManager: eco.PackageManager,
		}, nil
	default:
		//nolint:nilnil // nil is a valid response in this case.
		return nil, nil
	}
}

func calculateVulnerablePathsCount(findings []testapi.FindingData) int {
	var count int
	for _, finding := range findings {
		if finding.Attributes == nil {
			continue
		}
		if finding.Attributes.Suppression != nil &&
			finding.Attributes.Suppression.Status == testapi.SuppressionStatusIgnored {
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
