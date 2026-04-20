package osmonitor_test

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/snyk/dep-graph/go/pkg/depgraph"
	"github.com/snyk/go-application-framework/pkg/analytics"
	gafclientmocks "github.com/snyk/go-application-framework/pkg/apiclients/mocks"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	"github.com/snyk/cli-extension-os-flows/internal/common"
	"github.com/snyk/cli-extension-os-flows/internal/errors"
	"github.com/snyk/cli-extension-os-flows/internal/instrumentation"
)

var (
	nopLogger  = zerolog.Nop()
	errFactory = errors.NewErrorFactory(&nopLogger)
	noopInst   = instrumentation.NewGAFInstrumentation(analytics.New())
)

func createMockEngine(ctrl *gomock.Controller) *mocks.MockEngine {
	return mocks.NewMockEngine(ctrl)
}

func setupMockTestClient(t *testing.T, ctrl *gomock.Controller) *gafclientmocks.MockTestClient {
	t.Helper()
	summary := &testapi.FindingSummary{
		Count: 0,
		CountBy: &map[string]map[string]uint32{
			"severity": {},
		},
	}

	mockTestResult := gafclientmocks.NewMockTestResult(ctrl)
	mockTestResult.EXPECT().GetExecutionState().Return(testapi.TestExecutionStatesFinished).AnyTimes()
	mockTestResult.EXPECT().Findings(gomock.Any()).Return([]testapi.FindingData{}, true, nil).AnyTimes()
	mockTestResult.EXPECT().GetTestSubject().Return(nil).AnyTimes()
	mockTestResult.EXPECT().GetEffectiveSummary().Return(summary).AnyTimes()
	mockTestResult.EXPECT().GetRawSummary().Return(summary).AnyTimes()
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

	mockTestHandle := gafclientmocks.NewMockTestHandle(ctrl)
	mockTestHandle.EXPECT().Wait(gomock.Any()).Return(nil).Times(1)
	mockTestHandle.EXPECT().Result().Return(mockTestResult).Times(1)

	mockTestClient := gafclientmocks.NewMockTestClient(ctrl)
	mockTestClient.EXPECT().StartTest(gomock.Any(), gomock.Any()).Return(mockTestHandle, nil).Times(1)

	return mockTestClient
}

func mustSetupMockTestResultEmpty(ctrl *gomock.Controller) *gafclientmocks.MockTestResult {
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
	return mockTestResult
}

// noopInstrumentation is unused but kept for reference; in tests we use the real
// GAFInstrumentation with nil analytics which is safe for recording calls.
var _ = require.NoError

func newSinglePkgDepgraphResolver() common.DepgraphResolver {
	return common.NewFakeDepgraphResolver([]common.DepgraphWithIdentity{
		{
			Identity: common.Identity{TargetFile: "proj/package.json"},
			DepGraph: &depgraph.DepGraph{
				SchemaVersion: "1.2.0",
				PkgManager:    depgraph.PkgManager{Name: "npm"},
				Pkgs: []depgraph.Pkg{
					{ID: "proj@1.0.0", Info: depgraph.PkgInfo{Name: "proj", Version: "1.0.0"}},
				},
				Graph: depgraph.Graph{RootNodeID: "root"},
			},
		},
	}, nil)
}

func setupDflyTestFixture(t *testing.T, ctrl *gomock.Controller) (ctx context.Context, orgID uuid.UUID, cfg configuration.Configuration) {
	t.Helper()
	orgID = uuid.New()
	mockIctx := createMockInvocationCtxWithURL(t, ctrl, nil)
	cfg = mockIctx.GetConfiguration()
	cfg.Set(configuration.ORGANIZATION, orgID.String())
	cfg.Set(configuration.INPUT_DIRECTORY, ".")

	ctx = t.Context()
	ctx = cmdctx.WithIctx(ctx, mockIctx)
	ctx = cmdctx.WithLogger(ctx, mockIctx.GetEnhancedLogger())
	ctx = cmdctx.WithProgressBar(ctx, mockIctx.GetUserInterface().NewProgressBar())
	ctx = cmdctx.WithConfig(ctx, cfg)
	ctx = cmdctx.WithErrorFactory(ctx, errFactory)
	ctx = cmdctx.WithInstrumentation(ctx, noopInst)

	return ctx, orgID, cfg
}

func setupCapturingTestClient(ctrl *gomock.Controller) (client *gafclientmocks.MockTestClient, getConfig func() *testapi.TestConfiguration) {
	mockTestResult := mustSetupMockTestResultEmpty(ctrl)
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
