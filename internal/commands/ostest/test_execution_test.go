package ostest_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/local_workflows/content_type"
	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/commands/ostest"
)

// mockTestResult is a mock implementation of testapi.TestResult for testing.
type mockTestResult struct {
	rawSummary       *testapi.FindingSummary
	effectiveSummary *testapi.FindingSummary
}

func (m *mockTestResult) GetRawSummary() *testapi.FindingSummary {
	return m.rawSummary
}

func (m *mockTestResult) GetEffectiveSummary() *testapi.FindingSummary {
	return m.effectiveSummary
}

// These methods are not used in newSummaryData but are required to satisfy the interface.
func (m *mockTestResult) GetTestSubject() testapi.TestSubject {
	return testapi.TestSubject{}
}

func (m *mockTestResult) Findings(_ context.Context) ([]testapi.FindingData, bool, error) {
	return nil, false, nil
}

func (m *mockTestResult) GetExecutionState() testapi.TestExecutionStates {
	return ""
}

func (m *mockTestResult) GetTestConfiguration() *testapi.TestConfiguration {
	return nil
}

func (m *mockTestResult) GetSubjectLocators() *[]testapi.TestSubjectLocator {
	return nil
}

func (m *mockTestResult) GetPassFail() *testapi.PassFail {
	return nil
}

func (m *mockTestResult) GetOutcomeReason() *testapi.TestOutcomeReason {
	return nil
}

func (m *mockTestResult) GetErrors() *[]testapi.IoSnykApiCommonError {
	return nil
}

func (m *mockTestResult) GetWarnings() *[]testapi.IoSnykApiCommonError {
	return nil
}

func (m *mockTestResult) GetCreatedAt() *time.Time {
	return nil
}

func (m *mockTestResult) GetBreachedPolicies() *testapi.PolicyRefSet {
	return nil
}

func (m *mockTestResult) GetTestID() *uuid.UUID {
	return nil
}

func (m *mockTestResult) GetID() string {
	return ""
}

func Test_NewSummaryData(t *testing.T) {
	logger := zerolog.Nop()
	path := "/test/path"

	t.Run("no findings creates empty summary data, exit code 0", func(t *testing.T) {
		testResult := &mockTestResult{
			rawSummary:       &testapi.FindingSummary{Count: 0},
			effectiveSummary: &testapi.FindingSummary{Count: 0},
		}

		summary, data, err := ostest.NewSummaryData(testResult, &logger, path)
		assert.NoError(t, err)
		assert.Equal(t,
			workflow.NewData(
				data.GetIdentifier(),
				content_type.TEST_SUMMARY,
				[]byte(`{"results":null,"severity_order_asc":["low","medium","high","critical"],"type":"open-source","artifacts":0,"path":"/test/path"}`),
			),
			data,
		)
		assert.Equal(t,
			&json_schemas.TestSummary{
				Results:          nil,
				SeverityOrderAsc: []string{"low", "medium", "high", "critical"},
				Type:             "open-source",
				Artifacts:        0,
				Path:             "/test/path",
			},
			summary,
		)
	})

	t.Run("no open or total findings should not create summary data", func(t *testing.T) {
		testResult := &mockTestResult{
			rawSummary: &testapi.FindingSummary{
				Count: 0,
				CountBy: &map[string]map[string]uint32{
					"severity": {"high": 0},
				},
			},
			effectiveSummary: &testapi.FindingSummary{
				Count: 0,
				CountBy: &map[string]map[string]uint32{
					"severity": {"high": 0},
				},
			},
		}

		summaryStruct, data, err := ostest.NewSummaryData(testResult, &logger, path)
		assert.NoError(t, err)
		assert.Equal(t,
			workflow.NewData(
				data.GetIdentifier(),
				content_type.TEST_SUMMARY,
				[]byte(`{"results":null,"severity_order_asc":["low","medium","high","critical"],"type":"open-source","artifacts":0,"path":"/test/path"}`),
			),
			data)
		assert.Equal(t,
			&json_schemas.TestSummary{
				Results:          nil,
				SeverityOrderAsc: []string{"low", "medium", "high", "critical"},
				Type:             "open-source",
				Artifacts:        0,
				Path:             "/test/path",
			},
			summaryStruct)
	})

	t.Run("one critical finding should create summary data, implying exit code 1", func(t *testing.T) {
		testResult := &mockTestResult{
			rawSummary: &testapi.FindingSummary{
				Count: 1,
				CountBy: &map[string]map[string]uint32{
					"severity": {"critical": 1},
				},
			},
			effectiveSummary: &testapi.FindingSummary{
				Count: 1,
				CountBy: &map[string]map[string]uint32{
					"severity": {"critical": 1},
				},
			},
		}

		summaryStruct, data, err := ostest.NewSummaryData(testResult, &logger, path)
		require.NoError(t, err)
		require.NotNil(t, data)
		require.NotNil(t, summaryStruct)

		assert.Equal(t, content_type.TEST_SUMMARY, data.GetContentType())

		var summary json_schemas.TestSummary
		payload, ok := data.GetPayload().([]byte)
		require.True(t, ok)
		err = json.Unmarshal(payload, &summary)
		require.NoError(t, err)

		assert.Equal(t, "open-source", summary.Type)
		assert.Equal(t, path, summary.Path)
		require.Len(t, summary.Results, 1)
		assert.Equal(t, "critical", summary.Results[0].Severity)
		assert.Equal(t, 1, summary.Results[0].Total)
		assert.Equal(t, 1, summary.Results[0].Open)
		assert.Equal(t, 0, summary.Results[0].Ignored)

		// also check the returned struct
		assert.Equal(t, "open-source", summaryStruct.Type)
		assert.Equal(t, path, summaryStruct.Path)
		require.Len(t, summaryStruct.Results, 1)
		assert.Equal(t, "critical", summaryStruct.Results[0].Severity)
	})

	t.Run("multiple findings with ignored", func(t *testing.T) {
		testResult := &mockTestResult{
			rawSummary: &testapi.FindingSummary{
				Count: 3,
				CountBy: &map[string]map[string]uint32{
					"severity": {
						"high":   2,
						"medium": 1,
					},
				},
			},
			effectiveSummary: &testapi.FindingSummary{
				Count: 1,
				CountBy: &map[string]map[string]uint32{
					"severity": {
						"high": 1,
					},
				},
			},
		}

		summaryStruct, data, err := ostest.NewSummaryData(testResult, &logger, path)
		require.NoError(t, err)
		require.NotNil(t, data)
		require.NotNil(t, summaryStruct)

		// Verify content type is set correctly
		assert.Equal(t, content_type.TEST_SUMMARY, data.GetContentType())

		var summary json_schemas.TestSummary
		payload, ok := data.GetPayload().([]byte)
		require.True(t, ok)
		err = json.Unmarshal(payload, &summary)
		require.NoError(t, err)

		require.Len(t, summary.Results, 2)
		// Results are sorted by severity descending
		assert.Equal(t, "high", summary.Results[0].Severity)
		assert.Equal(t, 2, summary.Results[0].Total)
		assert.Equal(t, 1, summary.Results[0].Open)
		assert.Equal(t, 1, summary.Results[0].Ignored)

		assert.Equal(t, "medium", summary.Results[1].Severity)
		assert.Equal(t, 1, summary.Results[1].Total)
		assert.Equal(t, 0, summary.Results[1].Open)
		assert.Equal(t, 1, summary.Results[1].Ignored)
	})

	t.Run("summary is nil", func(t *testing.T) {
		testResult := &mockTestResult{
			rawSummary:       nil,
			effectiveSummary: nil,
		}

		summary, data, err := ostest.NewSummaryData(testResult, &logger, path)
		assert.Nil(t, data)
		assert.Nil(t, summary)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "test result missing summary information")
	})

	t.Run("newWorkflowData creates correct content types", func(t *testing.T) {
		// Test legacy findings content type
		legacyData := []byte(`{"findings": "data"}`)
		legacyWorkflowData := ostest.NewWorkflowData(ostest.ApplicationJSONContentType, legacyData)
		assert.Equal(t, ostest.ApplicationJSONContentType, legacyWorkflowData.GetContentType())
		assert.Equal(t, legacyData, legacyWorkflowData.GetPayload())

		// Test summary content type
		summaryData := []byte(`{"summary": "data"}`)
		summaryWorkflowData := ostest.NewWorkflowData(content_type.TEST_SUMMARY, summaryData)
		assert.Equal(t, content_type.TEST_SUMMARY, summaryWorkflowData.GetContentType())
		assert.Equal(t, summaryData, summaryWorkflowData.GetPayload())
	})
}
