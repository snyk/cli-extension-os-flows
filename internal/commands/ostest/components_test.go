package ostest_test

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	gafclientmocks "github.com/snyk/go-application-framework/pkg/apiclients/mocks"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/commands/ostest"
	"github.com/snyk/cli-extension-os-flows/internal/util"
)

// findingInComponent builds a finding attributed to the given component key. An empty key
// produces a finding the test API did not attribute to any component.
func findingInComponent(title, componentKey string) testapi.FindingData {
	attrs := &testapi.FindingAttributes{Title: title}
	if componentKey != "" {
		attrs.ComponentKey = util.Ptr(componentKey)
	}
	return testapi.FindingData{Attributes: attrs}
}

// resultWithComponents builds a test result reporting the given components.
func resultWithComponents(t *testing.T, components ...testapi.TestComponent) testapi.TestResult {
	t.Helper()

	ctrl := gomock.NewController(t)
	result := gafclientmocks.NewMockTestResult(ctrl)
	result.EXPECT().Get(testapi.TestResultComponents).Return(&components).AnyTimes()
	return result
}

func scaComponent(key string, projectID *uuid.UUID) testapi.TestComponent {
	return testapi.TestComponent{
		Key:       key,
		ProjectId: projectID,
		ScanType:  testapi.FindingType("sca"),
	}
}

func titlesOf(findings []testapi.FindingData) []string {
	titles := make([]string, 0, len(findings))
	for _, finding := range findings {
		titles = append(titles, finding.Attributes.Title)
	}
	return titles
}

func Test_SplitFindingsByComponent_GroupsByComponentKey(t *testing.T) {
	projectID := uuid.New()
	result := resultWithComponents(t,
		scaComponent("pkg:npm/app-a@1.0.0", &projectID),
		scaComponent("pkg:npm/app-b@2.0.0", nil),
	)
	findings := []testapi.FindingData{
		findingInComponent("a1", "pkg:npm/app-a@1.0.0"),
		findingInComponent("b1", "pkg:npm/app-b@2.0.0"),
		findingInComponent("a2", "pkg:npm/app-a@1.0.0"),
	}

	split := ostest.SplitFindingsByComponent(result, findings)

	require.Len(t, split, 2)

	assert.Equal(t, "pkg:npm/app-a@1.0.0", split[0].Key)
	assert.Equal(t, []string{"a1", "a2"}, titlesOf(split[0].Findings))
	require.NotNil(t, split[0].ProjectID)
	assert.Equal(t, projectID, *split[0].ProjectID)

	assert.Equal(t, "pkg:npm/app-b@2.0.0", split[1].Key)
	assert.Equal(t, []string{"b1"}, titlesOf(split[1].Findings))
	assert.Nil(t, split[1].ProjectID)
}

func Test_SplitFindingsByComponent_KeepsComponentsWithoutFindings(t *testing.T) {
	result := resultWithComponents(t,
		scaComponent("pkg:npm/vulnerable@1.0.0", nil),
		scaComponent("pkg:npm/clean@1.0.0", nil),
	)
	findings := []testapi.FindingData{findingInComponent("only-one", "pkg:npm/vulnerable@1.0.0")}

	split := ostest.SplitFindingsByComponent(result, findings)

	require.Len(t, split, 2)
	assert.Equal(t, "pkg:npm/clean@1.0.0", split[1].Key)
	assert.Empty(t, split[1].Findings)
}

func Test_SplitFindingsByComponent_OrdersByReportedComponents(t *testing.T) {
	// The findings arrive in the opposite order to the reported components.
	result := resultWithComponents(t,
		scaComponent("first", nil),
		scaComponent("second", nil),
	)
	findings := []testapi.FindingData{
		findingInComponent("s", "second"),
		findingInComponent("f", "first"),
	}

	split := ostest.SplitFindingsByComponent(result, findings)

	require.Len(t, split, 2)
	assert.Equal(t, "first", split[0].Key)
	assert.Equal(t, "second", split[1].Key)
}

func Test_SplitFindingsByComponent_AppendsKeysMissingFromTestResult(t *testing.T) {
	result := resultWithComponents(t, scaComponent("reported", nil))
	findings := []testapi.FindingData{
		findingInComponent("u", "unreported"),
		findingInComponent("r", "reported"),
	}

	split := ostest.SplitFindingsByComponent(result, findings)

	require.Len(t, split, 2)
	assert.Equal(t, "reported", split[0].Key)
	assert.Equal(t, "unreported", split[1].Key)
	assert.Equal(t, []string{"u"}, titlesOf(split[1].Findings))
}

func Test_SplitFindingsByComponent_ReportsUnattributedFindingsLast(t *testing.T) {
	result := resultWithComponents(t, scaComponent("known", nil))
	findings := []testapi.FindingData{
		findingInComponent("orphan", ""),
		findingInComponent("attributed", "known"),
	}

	split := ostest.SplitFindingsByComponent(result, findings)

	require.Len(t, split, 2)
	assert.Equal(t, "known", split[0].Key)
	assert.Empty(t, split[1].Key)
	assert.Equal(t, []string{"orphan"}, titlesOf(split[1].Findings))
}

func Test_SplitFindingsByComponent_DeduplicatesRepeatedComponentKeys(t *testing.T) {
	// The same component can be reported once per scan type.
	result := resultWithComponents(t,
		scaComponent("shared", nil),
		testapi.TestComponent{Key: "shared", ScanType: testapi.FindingType("sast")},
	)
	findings := []testapi.FindingData{findingInComponent("one", "shared")}

	split := ostest.SplitFindingsByComponent(result, findings)

	require.Len(t, split, 1)
	assert.Equal(t, []string{"one"}, titlesOf(split[0].Findings))
}

func Test_SplitFindingsByComponent_NoComponentInformation(t *testing.T) {
	tests := map[string]struct {
		result   testapi.TestResult
		findings []testapi.FindingData
	}{
		"no components and no component keys": {
			result:   resultWithComponents(t),
			findings: []testapi.FindingData{findingInComponent("a", ""), findingInComponent("b", "")},
		},
		"no findings at all": {
			result:   resultWithComponents(t),
			findings: nil,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// nil signals the caller to report a single, unsplit result.
			assert.Nil(t, ostest.SplitFindingsByComponent(tc.result, tc.findings))
		})
	}
}

func Test_SplitFindingsByComponent_NilComponentsOnResult(t *testing.T) {
	ctrl := gomock.NewController(t)
	result := gafclientmocks.NewMockTestResult(ctrl)
	result.EXPECT().Get(testapi.TestResultComponents).Return(nil).AnyTimes()

	findings := []testapi.FindingData{findingInComponent("a", "pkg:npm/app@1.0.0")}

	split := ostest.SplitFindingsByComponent(result, findings)

	// The component key on the finding is enough to split on.
	require.Len(t, split, 1)
	assert.Equal(t, "pkg:npm/app@1.0.0", split[0].Key)
}
