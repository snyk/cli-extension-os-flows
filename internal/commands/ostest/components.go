package ostest

import (
	"github.com/google/uuid"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
)

// ComponentFindings holds the findings belonging to a single component of a test.
type ComponentFindings struct {
	Key       string
	ProjectID *uuid.UUID
	Findings  []testapi.FindingData
}

// SplitFindingsByComponent groups findings by the component they originated in.
func SplitFindingsByComponent(result testapi.TestResult, findings []testapi.FindingData) []ComponentFindings {
	byKey := make(map[string][]testapi.FindingData, len(findings))
	var keyOrder []string
	for _, finding := range findings {
		key := findingComponentKey(finding)
		if _, ok := byKey[key]; !ok {
			keyOrder = append(keyOrder, key)
		}
		byKey[key] = append(byKey[key], finding)
	}

	components := testResultComponents(result)
	if len(components) == 0 && !hasComponentKey(keyOrder) {
		return nil
	}

	split := make([]ComponentFindings, 0, len(components)+len(keyOrder))
	seen := make(map[string]bool, len(components))

	for _, component := range components {
		if component.Key == "" || seen[component.Key] {
			continue
		}
		seen[component.Key] = true
		split = append(split, ComponentFindings{
			Key:       component.Key,
			ProjectID: component.ProjectId,
			Findings:  byKey[component.Key],
		})
	}

	for _, key := range keyOrder {
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		split = append(split, ComponentFindings{Key: key, Findings: byKey[key]})
	}

	if unattributed := byKey[""]; len(unattributed) > 0 {
		split = append(split, ComponentFindings{Findings: unattributed})
	}

	if len(split) == 0 {
		return nil
	}
	return split
}

func hasComponentKey(keys []string) bool {
	for _, key := range keys {
		if key != "" {
			return true
		}
	}
	return false
}

func findingComponentKey(finding testapi.FindingData) string {
	if finding.Attributes == nil || finding.Attributes.ComponentKey == nil {
		return ""
	}
	return *finding.Attributes.ComponentKey
}

func testResultComponents(result testapi.TestResult) []testapi.TestComponent {
	if result == nil {
		return nil
	}
	components, ok := result.Get(testapi.TestResultComponents).(*[]testapi.TestComponent)
	if !ok || components == nil {
		return nil
	}
	return *components
}

func componentKeys(split []ComponentFindings) []string {
	keys := make([]string, 0, len(split))
	for _, component := range split {
		keys = append(keys, component.Key)
	}
	return keys
}
