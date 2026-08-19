package ostest

import (
	"context"
	"maps"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
)

type componentTestResult struct {
	testapi.TestResult

	findings   []testapi.FindingData
	components []testapi.TestComponent
	metadata   map[string]interface{}
	effective  *testapi.FindingSummary
	raw        *testapi.FindingSummary
}

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

func resultMetadata(result testapi.TestResult) map[string]interface{} {
	metadata, ok := result.Get(testapi.TestResultMetadata).(map[string]interface{})
	if !ok {
		return nil
	}
	return metadata
}
