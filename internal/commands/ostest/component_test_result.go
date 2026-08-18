package ostest

import (
	"context"
	"maps"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
)

// Metadata keys that describe the test run as a whole rather than any one component. They
// are lifted onto the test itself, so that splitting a test's results does not report the
// same value under every component.
var testWideMetadataKeys = []string{"asset", "report-url"}

// splitTestWideMetadata separates the metadata describing the test as a whole from the
// metadata describing a result, returning the test-wide part and leaving metadata with the
// rest.
func splitTestWideMetadata(metadata map[string]interface{}) map[string]interface{} {
	testWide := map[string]interface{}{}
	for _, key := range testWideMetadataKeys {
		if value, ok := metadata[key]; ok {
			testWide[key] = value
			delete(metadata, key)
		}
	}

	if len(testWide) == 0 {
		return nil
	}
	return testWide
}

// componentTestResult presents a single component of a test as a test result in its own right.
//
// The test API reports an SBOM test as one test covering many components, but the unified
// findings presenter renders one section per test result. Wrapping each component as its own
// result gives SBOM tests the same per-project output as `snyk test --all-projects`, where
// every project genuinely is a separate test.
//
// Everything not scoped to a component is delegated to the underlying test result.
type componentTestResult struct {
	testapi.TestResult

	findings   []testapi.FindingData
	components []testapi.TestComponent
	metadata   map[string]interface{}
	effective  *testapi.FindingSummary
	raw        *testapi.FindingSummary
}

// newComponentTestResult wraps result as the test result for a single component.
func newComponentTestResult(
	result testapi.TestResult,
	component ComponentFindings,
	metadata map[string]interface{},
) *componentTestResult {
	componentResult := &componentTestResult{
		TestResult: result,
		findings:   component.Findings,
		metadata:   metadata,
		effective:  summarizeFindings(component.Findings, true),
		raw:        summarizeFindings(component.Findings, false),
	}

	if component.Key != "" {
		componentResult.components = []testapi.TestComponent{{
			Key:       component.Key,
			ScanType:  testapi.FindingTypeSca,
			ProjectId: component.ProjectID,
		}}
	}

	return componentResult
}

func (c *componentTestResult) Findings(context.Context) ([]testapi.FindingData, bool, error) {
	return c.findings, true, nil
}

func (c *componentTestResult) Get(key testapi.TestResultKeys) interface{} {
	switch key {
	case testapi.TestResultMetadata:
		return c.metadata
	case testapi.TestResultComponents:
		if c.components == nil {
			return nil
		}
		return &c.components
	case testapi.TestResultRawSummary:
		return c.raw
	default:
		return c.TestResult.Get(key)
	}
}

func (c *componentTestResult) GetMetadata() map[string]interface{} {
	return c.metadata
}

func (c *componentTestResult) GetMetadataValue(key string) interface{} {
	return c.metadata[key]
}

func (c *componentTestResult) SetMetadata(key string, value interface{}) {
	c.metadata[key] = value
}

func (c *componentTestResult) GetEffectiveSummary() *testapi.FindingSummary {
	return c.effective
}

func (c *componentTestResult) GetRawSummary() *testapi.FindingSummary {
	return c.raw
}

// componentTestResults wraps each component as its own test result. Component metadata is
// derived from the base metadata so that anything the flow set on the test as a whole, such
// as the package manager, is carried over.
func componentTestResults(
	result testapi.TestResult,
	split []ComponentFindings,
	targets []testTarget,
	targetDir string,
) []testapi.TestResult {
	baseMetadata := resultMetadata(result)

	results := make([]testapi.TestResult, 0, len(split))
	for i := range split {
		metadata := maps.Clone(baseMetadata)
		if metadata == nil {
			metadata = map[string]interface{}{}
		}

		metadata["package-manager"] = targets[i].packageManager
		metadata["project-name"] = targets[i].projectName
		metadata["display-target-file"] = targets[i].displayTargetFile
		metadata["target-directory"] = targetDir
		metadata["dependency-count"] = targets[i].depCount

		results = append(results, newComponentTestResult(result, split[i], metadata))
	}
	return results
}

// summarizeFindings counts findings by severity. When effective is true, findings suppressed
// by policy are left out, matching the distinction the test API draws between its effective
// and raw summaries.
func summarizeFindings(findings []testapi.FindingData, effective bool) *testapi.FindingSummary {
	bySeverity := map[string]uint32{}
	var count uint32

	for _, finding := range findings {
		if finding.Attributes == nil {
			continue
		}
		if effective && isSuppressed(finding) {
			continue
		}
		count++
		bySeverity[string(finding.Attributes.Rating.Severity)]++
	}

	return &testapi.FindingSummary{
		Count:   count,
		CountBy: &map[string]map[string]uint32{"severity": bySeverity},
	}
}

func isSuppressed(finding testapi.FindingData) bool {
	return finding.Attributes.Suppression != nil &&
		finding.Attributes.Suppression.Status == testapi.SuppressionStatusIgnored
}

// resultMetadata returns the metadata recorded on a test result, or nil if it has none.
func resultMetadata(result testapi.TestResult) map[string]interface{} {
	metadata, ok := result.Get(testapi.TestResultMetadata).(map[string]interface{})
	if !ok {
		return nil
	}
	return metadata
}
