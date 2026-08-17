package ostest

import (
	"github.com/google/uuid"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
)

// ComponentFindings holds the findings belonging to a single component of a test.
//
// A test run against an SBOM covers every component in that document, but the test
// API reports the whole run as a single test. Splitting the findings back out per
// component lets the SBOM flow report one result per component, matching how
// `snyk test --all-projects` reports one result per project.
type ComponentFindings struct {
	// Key is the test-scoped component key. It is empty for findings the test API
	// did not attribute to any component.
	Key string
	// ProjectID is the Snyk project associated with the component, if any.
	ProjectID *uuid.UUID
	// Findings are the findings that originated in the component.
	Findings []testapi.FindingData
}

// SplitFindingsByComponent groups findings by the component they originated in.
//
// The components reported on the test result are the canonical, ordered list, so a
// component without findings still gets an entry and therefore still gets its own
// result. Component keys seen only on a finding are appended afterwards, followed by
// any findings that carry no component key at all.
//
// It returns nil when the test result carries no component information, in which case
// the caller should report the findings as a single, unsplit result.
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

	// A single component may be reported once per scan type, so de-duplicate by key.
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

	// Report unattributed findings last, under the flow's own target file, rather
	// than dropping them.
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

// componentKeys lists the keys of the split components, for logging.
func componentKeys(split []ComponentFindings) []string {
	keys := make([]string, 0, len(split))
	for _, component := range split {
		keys = append(keys, component.Key)
	}
	return keys
}
