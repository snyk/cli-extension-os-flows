package ostest_test

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/apiclients/fileupload"
	gafclientmocks "github.com/snyk/go-application-framework/pkg/apiclients/mocks"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	gafmocks "github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/snyk/go-application-framework/pkg/utils"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	"github.com/snyk/cli-extension-os-flows/internal/commands/ostest"
	common "github.com/snyk/cli-extension-os-flows/internal/common"
	"github.com/snyk/cli-extension-os-flows/internal/constants"
	"github.com/snyk/cli-extension-os-flows/internal/deeproxy"
	"github.com/snyk/cli-extension-os-flows/internal/errors"
	"github.com/snyk/cli-extension-os-flows/internal/mocks"
	"github.com/snyk/cli-extension-os-flows/internal/reachability"
	"github.com/snyk/cli-extension-os-flows/pkg/flags"
)

var orgUUID = uuid.MustParse("8c2def96-233c-41b2-ab52-590c016e81e0")

type flowTestHarness struct {
	t      *testing.T
	ctrl   *gomock.Controller
	cfg    configuration.Configuration
	engine *gafmocks.MockEngine
	ictx   *gafmocks.MockInvocationContext
	instr  *mocks.MockInstrumentation
	logger zerolog.Logger
}

func newFlowTestHarness(t *testing.T) *flowTestHarness {
	t.Helper()

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	cfg := configuration.New()
	cfg.Set(constants.FeatureFlagRiskScore, true)
	cfg.Set(constants.FeatureFlagRiskScoreInCLI, true)

	logger := zerolog.Nop()
	engine := gafmocks.NewMockEngine(ctrl)
	ictx := gafmocks.NewMockInvocationContext(ctrl)
	instr := mocks.NewMockInstrumentation(ctrl)

	ictx.EXPECT().GetConfiguration().Return(cfg).AnyTimes()
	ictx.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
	ictx.EXPECT().GetRuntimeInfo().Return(runtimeinfo.New()).AnyTimes()
	ictx.EXPECT().GetWorkflowIdentifier().Return(common.DepGraphWorkflowID).AnyTimes()
	ictx.EXPECT().GetEngine().Return(engine).AnyTimes()

	return &flowTestHarness{
		t:      t,
		ctrl:   ctrl,
		cfg:    cfg,
		engine: engine,
		ictx:   ictx,
		instr:  instr,
		logger: logger,
	}
}

func (h *flowTestHarness) buildContext() context.Context {
	h.t.Helper()
	ef := errors.NewErrorFactory(&h.logger)
	ctx := h.t.Context()
	ctx = cmdctx.WithIctx(ctx, h.ictx)
	ctx = cmdctx.WithConfig(ctx, h.cfg)
	ctx = cmdctx.WithLogger(ctx, &h.logger)
	ctx = cmdctx.WithErrorFactory(ctx, ef)
	ctx = cmdctx.WithProgressBar(ctx, &nopProgressBar)
	ctx = cmdctx.WithInstrumentation(ctx, h.instr)
	return ctx
}

func (h *flowTestHarness) defaultClients(testClient testapi.TestClient) ostest.FlowClients {
	return ostest.FlowClients{
		TestClient:       testClient,
		FileUploadClient: fileupload.NewFakeClient(),
	}
}

func (h *flowTestHarness) registerDepGraphs(n int) {
	h.t.Helper()
	datas := newMockDepGraphDatas(h.t, h.ctrl, n)
	h.engine.EXPECT().InvokeWithConfig(common.DepGraphWorkflowID, gomock.Any()).Return(datas, nil).Times(1)
}

func newMockDepGraphData(t *testing.T, ctrl *gomock.Controller) workflow.Data {
	t.Helper()
	dg := testapi.IoSnykApiV1testdepgraphRequestDepGraph{
		SchemaVersion: "1.2.0",
		PkgManager:    testapi.IoSnykApiV1testdepgraphRequestPackageManager{Name: "npm"},
		Pkgs: []testapi.IoSnykApiV1testdepgraphRequestPackage{
			{Id: "proj@1.0.0", Info: testapi.IoSnykApiV1testdepgraphRequestPackageInfo{Name: "proj", Version: "1.0.0"}},
		},
		Graph: testapi.IoSnykApiV1testdepgraphRequestGraph{RootNodeId: "root"},
	}
	b, err := json.Marshal(dg)
	require.NoError(t, err)

	d := gafmocks.NewMockData(ctrl)
	d.EXPECT().GetPayload().Return(b).AnyTimes()
	d.EXPECT().GetMetaData(common.NormalisedTargetFileKey).Return("proj/package.json", nil).AnyTimes()
	d.EXPECT().GetMetaData(common.TargetFileFromPluginKey).Return("proj/package.json", nil).AnyTimes()
	d.EXPECT().GetMetaData(common.TargetKey).Return("{}", nil).AnyTimes()
	return d
}

func newMockDepGraphDatas(t *testing.T, ctrl *gomock.Controller, n int) []workflow.Data {
	t.Helper()
	datas := make([]workflow.Data, 0, n)
	for range n {
		datas = append(datas, newMockDepGraphData(t, ctrl))
	}
	return datas
}

func newPassingTestResult(ctrl *gomock.Controller) *gafclientmocks.MockTestResult {
	result := gafclientmocks.NewMockTestResult(ctrl)
	result.EXPECT().GetExecutionState().Return(testapi.TestExecutionStatesFinished).AnyTimes()
	result.EXPECT().Findings(gomock.Any()).Return([]testapi.FindingData{}, true, nil).AnyTimes()
	result.EXPECT().GetSubjectLocators().Return(nil).AnyTimes()
	result.EXPECT().GetTestID().Return(&uuid.UUID{}).AnyTimes()
	result.EXPECT().GetTestConfiguration().Return(&testapi.TestConfiguration{}).AnyTimes()
	result.EXPECT().GetCreatedAt().Return(&time.Time{}).AnyTimes()
	result.EXPECT().GetErrors().Return(&[]testapi.IoSnykApiCommonError{}).AnyTimes()
	result.EXPECT().GetWarnings().Return(&[]testapi.IoSnykApiCommonError{}).AnyTimes()
	passFail := testapi.Pass
	result.EXPECT().GetPassFail().Return(&passFail).AnyTimes()
	outcomeReason := testapi.TestOutcomeReasonOther
	result.EXPECT().GetOutcomeReason().Return(&outcomeReason).AnyTimes()
	result.EXPECT().SetMetadata(gomock.Any(), gomock.Any()).Return().AnyTimes()
	result.EXPECT().GetMetadata().Return(make(map[string]interface{})).AnyTimes()
	result.EXPECT().GetTestFacts().Return(nil).AnyTimes()
	result.EXPECT().GetBreachedPolicies().Return(&testapi.PolicyRefSet{}).AnyTimes()
	result.EXPECT().GetTestSubject().Return(&testapi.TestSubject{}).AnyTimes()
	result.EXPECT().GetEffectiveSummary().Return(&testapi.FindingSummary{}).AnyTimes()
	result.EXPECT().GetRawSummary().Return(&testapi.FindingSummary{}).AnyTimes()
	return result
}

func newAssertingTestClient(
	t *testing.T,
	ctrl *gomock.Controller,
	assertFn func(t *testing.T, params testapi.StartTestParams),
) *gafclientmocks.MockTestClient {
	t.Helper()
	client := gafclientmocks.NewMockTestClient(ctrl)
	client.EXPECT().StartTest(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, params testapi.StartTestParams) (testapi.TestHandle, error) {
			assertFn(t, params)
			handle := gafclientmocks.NewMockTestHandle(ctrl)
			handle.EXPECT().Wait(gomock.Any()).Return(nil).Times(1)
			result := newPassingTestResult(ctrl)
			handle.EXPECT().Result().Return(result).Times(1)
			return handle, nil
		},
	).Times(1)
	return client
}

func Test_RunUnifiedTestFlow_ConcurrencyLimit(t *testing.T) {
	t.Parallel()
	h := newFlowTestHarness(t)

	h.cfg.Set(flags.FlagAllProjects, true)
	h.cfg.Set(configuration.MAX_THREADS, 99)
	h.instr.EXPECT().RecordOSAnalysisTime(gomock.Any()).Times(1)

	const n = 12
	h.registerDepGraphs(n)

	var current, peak atomic.Int32
	mockTestClient := gafclientmocks.NewMockTestClient(h.ctrl)
	mockTestClient.EXPECT().StartTest(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, _ testapi.StartTestParams) (testapi.TestHandle, error) {
			handle := gafclientmocks.NewMockTestHandle(h.ctrl)
			handle.EXPECT().Wait(gomock.Any()).DoAndReturn(func(_ context.Context) error {
				c := current.Add(1)
				for {
					m := peak.Load()
					if c > m {
						if peak.CompareAndSwap(m, c) {
							break
						}
						continue
					}
					break
				}
				time.Sleep(50 * time.Millisecond)
				current.Add(-1)
				return nil
			}).Times(1)
			result := newPassingTestResult(h.ctrl)
			handle.EXPECT().Result().Return(result).Times(1)
			return handle, nil
		},
	).Times(n)

	ctx := h.buildContext()
	_, _, err := ostest.RunUnifiedTestFlow(ctx, ".", h.defaultClients(mockTestClient), orgUUID, nil, nil)
	require.NoError(t, err)

	const limit int32 = 5
	require.LessOrEqualf(t, peak.Load(), limit, "observed concurrency %d exceeds limit %d", peak.Load(), limit)
}

func Test_RunUnifiedTestFlow_ConcurrencyLimitHonorsMaxThreads(t *testing.T) {
	t.Parallel()
	h := newFlowTestHarness(t)

	h.cfg.Set(configuration.MAX_THREADS, 3)
	h.cfg.Set(flags.FlagAllProjects, true)
	h.instr.EXPECT().RecordOSAnalysisTime(gomock.Any()).Times(1)

	const n = 10
	h.registerDepGraphs(n)

	var current, peak atomic.Int32
	mockTestClient := gafclientmocks.NewMockTestClient(h.ctrl)
	mockTestClient.EXPECT().StartTest(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, _ testapi.StartTestParams) (testapi.TestHandle, error) {
			handle := gafclientmocks.NewMockTestHandle(h.ctrl)
			handle.EXPECT().Wait(gomock.Any()).DoAndReturn(func(_ context.Context) error {
				c := current.Add(1)
				for {
					m := peak.Load()
					if c > m {
						if peak.CompareAndSwap(m, c) {
							break
						}
						continue
					}
					break
				}
				time.Sleep(50 * time.Millisecond)
				current.Add(-1)
				return nil
			}).Times(1)
			result := newPassingTestResult(h.ctrl)
			handle.EXPECT().Result().Return(result).Times(1)
			return handle, nil
		},
	).Times(n)

	ctx := h.buildContext()
	_, _, err := ostest.RunUnifiedTestFlow(ctx, ".", h.defaultClients(mockTestClient), orgUUID, nil, nil)
	require.NoError(t, err)

	const limit int32 = 3
	require.LessOrEqualf(t, peak.Load(), limit, "observed concurrency %d exceeds limit %d", peak.Load(), limit)
}

func Test_RunUnifiedTestFlow_DepGraphEnrichment(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		flagKey  string
		flagVal  any
		dgField  string
		expected any
	}{
		{
			name:     "ignorePolicy flag is set on depgraph",
			flagKey:  flags.FlagIgnorePolicy,
			flagVal:  true,
			dgField:  "ignorePolicy",
			expected: true,
		},
		{
			name:     "projectNameOverride flag is set on depgraph",
			flagKey:  flags.FlagProjectName,
			flagVal:  "my-custom-project-name",
			dgField:  "projectNameOverride",
			expected: "my-custom-project-name",
		},
		{
			name:     "targetReference flag is set on depgraph",
			flagKey:  flags.FlagTargetReference,
			flagVal:  "feature-branch-123",
			dgField:  "targetReference",
			expected: "feature-branch-123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newFlowTestHarness(t)

			h.cfg.Set(tt.flagKey, tt.flagVal)
			h.instr.EXPECT().RecordOSAnalysisTime(gomock.Any()).Times(1)
			h.registerDepGraphs(1)

			mockTestClient := newAssertingTestClient(t, h.ctrl, func(t *testing.T, params testapi.StartTestParams) {
				t.Helper()
				depGraphSubject, err := params.Subject().AsDepGraphSubjectCreate()
				require.NoError(t, err)

				value, exists := depGraphSubject.DepGraph.Get(tt.dgField)
				require.True(t, exists, "depgraph should have %s field set", tt.dgField)
				require.Equal(t, tt.expected, value)
			})

			ctx := h.buildContext()
			_, _, err := ostest.RunUnifiedTestFlow(ctx, ".", h.defaultClients(mockTestClient), orgUUID, nil, nil)
			require.NoError(t, err)
		})
	}
}

func Test_RunUnifiedTestFlow_CancelsOnError(t *testing.T) {
	t.Parallel()
	h := newFlowTestHarness(t)

	h.cfg.Set(flags.FlagAllProjects, true)

	const n = 6
	h.registerDepGraphs(n)

	var canceledCount atomic.Int32
	var callIndex atomic.Int32
	mockTestClient := gafclientmocks.NewMockTestClient(h.ctrl)
	mockTestClient.EXPECT().StartTest(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, _ testapi.StartTestParams) (testapi.TestHandle, error) {
			idx := callIndex.Add(1)
			handle := gafclientmocks.NewMockTestHandle(h.ctrl)
			handle.EXPECT().Wait(gomock.Any()).DoAndReturn(func(wctx context.Context) error {
				if idx == 1 {
					return fmt.Errorf("forced error")
				}
				select {
				case <-wctx.Done():
					canceledCount.Add(1)
					return wctx.Err()
				case <-time.After(2 * time.Second):
					return nil
				}
			}).Times(1)
			return handle, nil
		},
	).Times(n)

	runCtx, cancel := context.WithTimeout(h.buildContext(), 3*time.Second)
	defer cancel()

	_, _, err := ostest.RunUnifiedTestFlow(runCtx, ".", h.defaultClients(mockTestClient), orgUUID, nil, nil)
	require.Error(t, err)
	require.Positive(t, canceledCount.Load(), "expected at least one canceled sibling")
}

func Test_RunUnifiedTestFlow_ReachabilityFailureFallback(t *testing.T) {
	t.Parallel()
	h := newFlowTestHarness(t)

	h.instr.EXPECT().RecordCodeUploadTime(gomock.Any()).Times(1)
	h.instr.EXPECT().RecordOSAnalysisTime(gomock.Any()).Times(1)
	h.registerDepGraphs(1)

	mockTestClient := newAssertingTestClient(t, h.ctrl, func(t *testing.T, params testapi.StartTestParams) {
		t.Helper()
		depGraphSubject, err := params.Subject().AsDepGraphSubjectCreate()
		require.NoError(t, err)

		_, hasScanID := depGraphSubject.DepGraph.Get("reachabilityScanId")
		assert.False(t, hasScanID, "depgraph should NOT have reachabilityScanId when reachability failed")
	})

	fakeReachabilityClient := reachability.NewFakeClient(uuid.Nil)
	fakeReachabilityClient.WithStartErr(fmt.Errorf("simulated upload failure"))

	warnings := &[]string{}
	ctx := h.buildContext()
	ctx = cmdctx.WithWarnings(ctx, warnings)

	_, _, err := ostest.RunUnifiedTestFlow(ctx, ".", ostest.FlowClients{
		TestClient:         mockTestClient,
		FileUploadClient:   fileupload.NewFakeClient(),
		ReachabilityClient: fakeReachabilityClient,
		DeeproxyClient:     deeproxy.NewFakeClient(deeproxy.AllowList{Extensions: []string{".js"}}, nil),
	}, orgUUID, nil, &ostest.ReachabilityOpts{SourceDir: "."})

	require.NoError(t, err, "scan should succeed even when reachability fails")
	require.Len(t, *warnings, 1, "exactly one warning should be recorded")
	assert.Contains(t, (*warnings)[0], "simulated upload failure")
}

func TestMappingTargetParamsToDepGraph(t *testing.T) {
	rawDepGraph := common.RawDepGraphWithMeta{
		Payload:              []byte(`{}`),
		NormalisedTargetFile: "some normalised target file",
		TargetFileFromPlugin: utils.Ptr("some target file from plugin"),
		Target:               []byte(`{ "remoteUrl":"https://remote.url", "branch":"main"}`),
	}

	depGraph, err := ostest.ParseDepGraph(rawDepGraph)

	require.NoError(t, err)
	require.Equal(t, "some normalised target file", depGraph.DisplayTargetFile)
	require.NotNil(t, depGraph.Payload)
	assert.Equal(t, "some target file from plugin", depGraph.Payload.AdditionalProperties["targetFile"])
	assert.Equal(t, json.RawMessage(`{ "remoteUrl":"https://remote.url", "branch":"main"}`), depGraph.Payload.AdditionalProperties["target"])
}

func TestMappingTargetParamsToDepGraph_WhenOptionalPropertiesAreMissing(t *testing.T) {
	rawDepGraph := common.RawDepGraphWithMeta{
		Payload:              []byte(`{}`),
		NormalisedTargetFile: "some normalised target file",
	}

	depGraph, err := ostest.ParseDepGraph(rawDepGraph)

	require.NoError(t, err)
	require.Equal(t, "some normalised target file", depGraph.DisplayTargetFile)
	require.NotNil(t, depGraph.Payload)
	assert.Nil(t, depGraph.Payload.AdditionalProperties["targetFile"])
	assert.Nil(t, depGraph.Payload.AdditionalProperties["target"])
}
