package ostest_test

import (
	"encoding/json"
	"testing"

	"github.com/golang/mock/gomock"
	gafclientmocks "github.com/snyk/go-application-framework/pkg/apiclients/mocks"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/local_workflows/content_type"
	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	"github.com/snyk/cli-extension-os-flows/internal/commands/ostest"
	xerrors "github.com/snyk/cli-extension-os-flows/internal/errors"
)

func Test_NewSummaryDataFromFindings(t *testing.T) {
	path := "/test/path"

	t.Run("no findings returns an empty summary", func(t *testing.T) {
		summary, data, err := ostest.NewSummaryDataFromFindings([]testapi.FindingData{}, path)
		assert.NoError(t, err)
		assert.NotNil(t, summary)
		assert.NotNil(t, data)
		assert.Empty(t, summary.Results)
	})

	t.Run("one critical finding should create summary data", func(t *testing.T) {
		findings := []testapi.FindingData{
			{
				Attributes: &testapi.FindingAttributes{
					Rating: testapi.Rating{
						Severity: testapi.SeverityCritical,
					},
				},
			},
		}

		summaryStruct, data, err := ostest.NewSummaryDataFromFindings(findings, path)
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

	t.Run("multiple findings are all considered open", func(t *testing.T) {
		findings := []testapi.FindingData{
			{
				Attributes: &testapi.FindingAttributes{
					Rating: testapi.Rating{
						Severity: testapi.SeverityHigh,
					},
				},
			},
			{
				Attributes: &testapi.FindingAttributes{
					Rating: testapi.Rating{
						Severity: testapi.SeverityHigh,
					},
				},
			},
			{
				Attributes: &testapi.FindingAttributes{
					Rating: testapi.Rating{
						Severity: testapi.SeverityMedium,
					},
				},
			},
		}

		summaryStruct, data, err := ostest.NewSummaryDataFromFindings(findings, path)
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
		assert.Equal(t, 2, summary.Results[0].Open)
		assert.Equal(t, 0, summary.Results[0].Ignored)

		assert.Equal(t, "medium", summary.Results[1].Severity)
		assert.Equal(t, 1, summary.Results[1].Total)
		assert.Equal(t, 1, summary.Results[1].Open)
		assert.Equal(t, 0, summary.Results[1].Ignored)
	})

	t.Run("nil findings slice returns an empty summary", func(t *testing.T) {
		summary, data, err := ostest.NewSummaryDataFromFindings(nil, path)
		assert.NoError(t, err)
		assert.NotNil(t, summary)
		assert.NotNil(t, data)
		assert.Empty(t, summary.Results)
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

// Test_RunTest_ErrorsWhenFindingsError verifies an error is returned when the Test passes but the Findings returns an error.
func Test_RunTest_ErrorsWhenFindingsError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockTestClient := gafclientmocks.NewMockTestClient(ctrl)
	mockHandle := gafclientmocks.NewMockTestHandle(ctrl)
	mockResult := gafclientmocks.NewMockTestResult(ctrl)

	// StartTest returns handle
	mockTestClient.EXPECT().StartTest(gomock.Any(), gomock.Any()).Return(mockHandle, nil)
	// Wait succeeds
	mockHandle.EXPECT().Wait(gomock.Any()).Return(nil)
	// Result reports Finished
	mockResult.EXPECT().GetExecutionState().Return(testapi.TestExecutionStatesFinished).AnyTimes()
	// Findings returns error (complete value doesn't matter for this case)
	mockResult.EXPECT().Findings(gomock.Any()).Return([]testapi.FindingData{{}}, true, assert.AnError)
	mockHandle.EXPECT().Result().Return(mockResult)

	ef := xerrors.NewErrorFactory(&logger)
	ctx := t.Context()
	ctx = cmdctx.WithLogger(ctx, &logger)
	ctx = cmdctx.WithErrorFactory(ctx, ef)
	ctx = cmdctx.WithProgressBar(ctx, &nopProgressBar)

	var subject testapi.TestSubjectCreate
	_ = subject.FromDepGraphSubjectCreate(testapi.DepGraphSubjectCreate{Type: testapi.DepGraphSubjectCreateTypeDepGraph})

	_, _, err := ostest.RunTest(ctx, ".", mockTestClient, subject, "", "", 0, "", "", "org", nil)
	require.Error(t, err)
}

// Test_RunTest_ErrorsWhenFindingsIncomplete verifies an error is returned when the Test passes but the Findings returns incomplete.
func Test_RunTest_ErrorsWhenFindingsIncomplete(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockTestClient := gafclientmocks.NewMockTestClient(ctrl)
	mockHandle := gafclientmocks.NewMockTestHandle(ctrl)
	mockResult := gafclientmocks.NewMockTestResult(ctrl)

	mockTestClient.EXPECT().StartTest(gomock.Any(), gomock.Any()).Return(mockHandle, nil)
	mockHandle.EXPECT().Wait(gomock.Any()).Return(nil)
	mockResult.EXPECT().GetExecutionState().Return(testapi.TestExecutionStatesFinished).AnyTimes()
	// Findings incomplete without error
	mockResult.EXPECT().Findings(gomock.Any()).Return([]testapi.FindingData{{}}, false, nil)
	mockHandle.EXPECT().Result().Return(mockResult)

	ef := xerrors.NewErrorFactory(&logger)
	ctx := t.Context()
	ctx = cmdctx.WithLogger(ctx, &logger)
	ctx = cmdctx.WithErrorFactory(ctx, ef)
	ctx = cmdctx.WithProgressBar(ctx, &nopProgressBar)

	var subject testapi.TestSubjectCreate
	_ = subject.FromDepGraphSubjectCreate(testapi.DepGraphSubjectCreate{Type: testapi.DepGraphSubjectCreateTypeDepGraph})

	_, _, err := ostest.RunTest(ctx, ".", mockTestClient, subject, "", "", 0, "", "", "org", nil)
	require.Error(t, err)
}
