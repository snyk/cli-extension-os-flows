//nolint:testpackage // Uses unexported executeFlow and helpers; keeping in-package keeps the test scope minimal.
package ostest

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/analytics"
	"github.com/snyk/go-application-framework/pkg/apiclients/fileupload"
	gafclientmocks "github.com/snyk/go-application-framework/pkg/apiclients/mocks"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	gafmocks "github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	"github.com/snyk/cli-extension-os-flows/internal/common"
	"github.com/snyk/cli-extension-os-flows/internal/errors"
	"github.com/snyk/cli-extension-os-flows/internal/instrumentation"
)

// progressBarStub is a minimal progress bar implementation for in-package tests.
type progressBarStub struct{}

func (*progressBarStub) SetTitle(_ string)                                    {}
func (*progressBarStub) UpdateProgress(_ float64) error                       { return nil }
func (*progressBarStub) Clear() error                                         { return nil }
func (*progressBarStub) SetCompletionMessage(_ string)                        {}
func (*progressBarStub) SetCompletionMessageWithStyle(_, _ string)            {}
func (*progressBarStub) SetCompletionMessageWithTitle(_, _ string)            {}
func (*progressBarStub) SetCompletionMessageWithTitleAndStyle(_, _, _ string) {}

func setupExecuteFlowCtx(t *testing.T, ctrl *gomock.Controller) (context.Context, configuration.Configuration) {
	t.Helper()
	cfg := configuration.New()
	cfg.Set(configuration.ORGANIZATION_SLUG, "test-org-slug")

	logger := zerolog.Nop()

	mockUI := gafmocks.NewMockUserInterface(ctrl)
	mockUI.EXPECT().Output(gomock.Any()).Return(nil).AnyTimes()
	mockUI.EXPECT().OutputError(gomock.Any()).Return(nil).AnyTimes()

	mockIctx := gafmocks.NewMockInvocationContext(ctrl)
	mockIctx.EXPECT().GetConfiguration().Return(cfg).AnyTimes()
	mockIctx.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
	mockIctx.EXPECT().GetRuntimeInfo().Return(runtimeinfo.New()).AnyTimes()
	mockIctx.EXPECT().GetWorkflowIdentifier().Return(workflow.NewWorkflowIdentifier("test")).AnyTimes()
	mockIctx.EXPECT().GetUserInterface().Return(mockUI).AnyTimes()

	ctx := t.Context()
	ctx = cmdctx.WithIctx(ctx, mockIctx)
	ctx = cmdctx.WithConfig(ctx, cfg)
	ctx = cmdctx.WithLogger(ctx, &logger)
	ctx = cmdctx.WithErrorFactory(ctx, errors.NewErrorFactory(&logger))
	ctx = cmdctx.WithProgressBar(ctx, &progressBarStub{})
	ctx = cmdctx.WithInstrumentation(ctx, instrumentation.NewGAFInstrumentation(analytics.New()))

	return ctx, cfg
}

func setupExecuteFlowCapturingTestClient(ctrl *gomock.Controller) (
	client *gafclientmocks.MockTestClient,
	getConfig func() *testapi.TestConfiguration,
) {
	mockTestResult := gafclientmocks.NewMockTestResult(ctrl)
	mockTestResult.EXPECT().GetExecutionState().Return(testapi.TestExecutionStatesFinished).AnyTimes()
	mockTestResult.EXPECT().Findings(gomock.Any()).Return([]testapi.FindingData{}, true, nil).AnyTimes()
	mockTestResult.EXPECT().GetTestSubject().Return(nil).AnyTimes()
	mockTestResult.EXPECT().GetEffectiveSummary().Return(&testapi.FindingSummary{}).AnyTimes()
	mockTestResult.EXPECT().GetRawSummary().Return(&testapi.FindingSummary{}).AnyTimes()
	mockTestResult.EXPECT().GetSubjectLocators().Return(nil).AnyTimes()
	mockTestResult.EXPECT().GetTestID().Return(&uuid.UUID{}).AnyTimes()
	mockTestResult.EXPECT().GetTestConfiguration().Return(&testapi.TestConfiguration{}).AnyTimes()
	mockTestResult.EXPECT().GetCreatedAt().Return(&time.Time{}).AnyTimes()
	mockTestResult.EXPECT().GetErrors().Return(&[]testapi.IoSnykApiCommonError{}).AnyTimes()
	mockTestResult.EXPECT().GetWarnings().Return(&[]testapi.IoSnykApiCommonError{}).AnyTimes()
	passFail := testapi.Pass
	outcomeReason := testapi.TestOutcomeReasonOther
	mockTestResult.EXPECT().GetPassFail().Return(&passFail).AnyTimes()
	mockTestResult.EXPECT().GetOutcomeReason().Return(&outcomeReason).AnyTimes()
	mockTestResult.EXPECT().SetMetadata(gomock.Any(), gomock.Any()).Return().AnyTimes()
	mockTestResult.EXPECT().GetMetadata().Return(make(map[string]interface{})).AnyTimes()
	mockTestResult.EXPECT().GetTestFacts().Return(nil).AnyTimes()
	mockTestResult.EXPECT().GetBreachedPolicies().Return(&testapi.PolicyRefSet{}).AnyTimes()
	mockTestResult.EXPECT().Get(testapi.TestResultTestSubject).Return(nil).AnyTimes()
	mockTestResult.EXPECT().Get(testapi.TestResultSubjectLocators).Return(nil).AnyTimes()
	mockTestResult.EXPECT().Get(testapi.TestResultBreachedPolicies).Return(&testapi.PolicyRefSet{}).AnyTimes()
	mockTestResult.EXPECT().Get(testapi.TestResultRawSummary).Return(&testapi.FindingSummary{}).AnyTimes()
	mockTestResult.EXPECT().Get(testapi.TestResultTestFacts).Return(nil).AnyTimes()
	mockTestResult.EXPECT().Get(testapi.TestResultMetadata).Return(make(map[string]interface{})).AnyTimes()
	mockTestResult.EXPECT().Get(testapi.TestResultComponents).Return(&[]testapi.TestComponent{}).AnyTimes()

	mockTestHandle := gafclientmocks.NewMockTestHandle(ctrl)
	mockTestHandle.EXPECT().Wait(gomock.Any()).Return(nil).Times(1)
	mockTestHandle.EXPECT().Result().Return(mockTestResult).Times(1)

	var capturedConfig *testapi.TestConfiguration
	mockTestClient := gafclientmocks.NewMockTestClient(ctrl)
	mockTestClient.EXPECT().StartTest(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ interface{}, params testapi.StartTestParams) (testapi.TestHandle, error) {
			capturedConfig = params.TestConfig()
			return mockTestHandle, nil
		},
	).Times(1)

	return mockTestClient, func() *testapi.TestConfiguration { return capturedConfig }
}

func Test_executeFlow_SbomFlow_PublishReportTrue_ForwardsToRunSbomFlow(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx, _ := setupExecuteFlowCtx(t, ctrl)
	orgUUID := uuid.New()
	ffc := fileupload.NewFakeClient()
	mockTestClient, getCapturedConfig := setupExecuteFlowCapturingTestClient(ctrl)

	clients := common.FlowClients{
		TestClient:       mockTestClient,
		FileUploadClient: ffc,
	}

	publishReport := true
	_, _, err := executeFlow(
		ctx,
		SbomFlow,
		clients,
		orgUUID,
		"./testdata",
		"",
		"./testdata/bom.json",
		nil,
		false,
		&publishReport,
	)
	require.NoError(t, err)

	capturedConfig := getCapturedConfig()
	require.NotNil(t, capturedConfig)
	require.NotNil(t, capturedConfig.PublishReport, "PublishReport must be forwarded into TestConfiguration")
	assert.True(t, *capturedConfig.PublishReport)
}

func Test_executeFlow_SbomFlow_PublishReportNil_PassesNilToRunSbomFlow(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx, _ := setupExecuteFlowCtx(t, ctrl)
	orgUUID := uuid.New()
	ffc := fileupload.NewFakeClient()
	mockTestClient, getCapturedConfig := setupExecuteFlowCapturingTestClient(ctrl)

	clients := common.FlowClients{
		TestClient:       mockTestClient,
		FileUploadClient: ffc,
	}

	_, _, err := executeFlow(
		ctx,
		SbomFlow,
		clients,
		orgUUID,
		"./testdata",
		"",
		"./testdata/bom.json",
		nil,
		false,
		nil,
	)
	require.NoError(t, err)

	capturedConfig := getCapturedConfig()
	require.NotNil(t, capturedConfig)
	assert.Nil(t, capturedConfig.PublishReport, "PublishReport must remain nil when not requested")
}
