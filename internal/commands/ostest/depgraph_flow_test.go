package ostest_test

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/snyk/go-application-framework/pkg/utils"
	"github.com/stretchr/testify/assert"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	gafclientmocks "github.com/snyk/go-application-framework/pkg/apiclients/mocks"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	gafmocks "github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	"github.com/snyk/cli-extension-os-flows/internal/commands/ostest"
	common "github.com/snyk/cli-extension-os-flows/internal/common"
	"github.com/snyk/cli-extension-os-flows/internal/errors"
	"github.com/snyk/cli-extension-os-flows/internal/flags"
)

// mockConcurrentStartTest sets up a mock TestClient whose Wait calls simulate concurrency
// and record the peak concurrency observed. Extracted to avoid duplication across tests.
func mockConcurrentStartTest(ctrl *gomock.Controller, n int, current, peak *atomic.Int32) *gafclientmocks.MockTestClient {
	mockTestClient := gafclientmocks.NewMockTestClient(ctrl)
	mockTestClient.EXPECT().StartTest(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, _ testapi.StartTestParams) (testapi.TestHandle, error) {
		handle := gafclientmocks.NewMockTestHandle(ctrl)
		// Wait: bump concurrency, sleep, then decrement
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

		// Result: minimal finished result with empty findings
		result := gafclientmocks.NewMockTestResult(ctrl)
		result.EXPECT().GetExecutionState().Return(testapi.TestExecutionStatesFinished).AnyTimes()
		result.EXPECT().Findings(gomock.Any()).Return([]testapi.FindingData{}, true, nil).AnyTimes()
		handle.EXPECT().Result().Return(result).Times(1)
		return handle, nil
	}).Times(n)
	return mockTestClient
}

// Test_RunUnifiedTestFlow_ConcurrencyLimit verifies that at most 5 depgraph tests run concurrently.
func Test_RunUnifiedTestFlow_ConcurrencyLimit(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Prepare mocks for InvocationContext and Engine to return many depgraphs
	mockEngine := gafmocks.NewMockEngine(ctrl)
	mockIctx := gafmocks.NewMockInvocationContext(ctrl)

	cfg := configuration.New()
	cfg.Set(ostest.FeatureFlagRiskScore, true)
	cfg.Set(ostest.FeatureFlagRiskScoreInCLI, true)
	cfg.Set(flags.FlagAllProjects, true)
	// Ensure the effective limit is the default (5)
	cfg.Set(configuration.MAX_THREADS, 99)

	logger := zerolog.Nop()

	mockIctx.EXPECT().GetConfiguration().Return(cfg).AnyTimes()
	mockIctx.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
	mockIctx.EXPECT().GetRuntimeInfo().Return(runtimeinfo.New()).AnyTimes()
	mockIctx.EXPECT().GetWorkflowIdentifier().Return(common.DepGraphWorkflowID).AnyTimes()
	// Engine is used by createDepGraphs
	mockIctx.EXPECT().GetEngine().Return(mockEngine).AnyTimes()

	// Build N depgraphs
	const n = 12
	depGraphDatas := make([]workflow.Data, 0, n)
	for i := 0; i < n; i++ {
		dg := testapi.IoSnykApiV1testdepgraphRequestDepGraph{
			SchemaVersion: "1.2.0",
			PkgManager:    testapi.IoSnykApiV1testdepgraphRequestPackageManager{Name: "npm"},
			Pkgs: []testapi.IoSnykApiV1testdepgraphRequestPackage{
				{Id: "proj@1.0.0", Info: testapi.IoSnykApiV1testdepgraphRequestPackageInfo{Name: "proj", Version: "1.0.0"}},
			},
			Graph: testapi.IoSnykApiV1testdepgraphRequestGraph{RootNodeId: "root"},
		}
		bytes, err := json.Marshal(dg)
		require.NoError(t, err)
		d := gafmocks.NewMockData(ctrl)
		d.EXPECT().GetPayload().Return(bytes).AnyTimes()
		d.EXPECT().GetMetaData(common.NormalisedTargetFileKey).Return("proj/package.json", nil).AnyTimes()
		d.EXPECT().GetMetaData(common.TargetFileFromPluginKey).Return("proj/package.json", nil).AnyTimes()
		d.EXPECT().GetMetaData(common.TargetKey).Return("{}", nil).AnyTimes()
		depGraphDatas = append(depGraphDatas, d)
	}

	mockEngine.EXPECT().InvokeWithConfig(common.DepGraphWorkflowID, gomock.Any()).Return(depGraphDatas, nil).Times(1)

	// Mock TestClient to track concurrency in their Wait calls.
	var current, peak atomic.Int32
	mockTestClient := mockConcurrentStartTest(ctrl, n, &current, &peak)

	// Run
	ef := errors.NewErrorFactory(&logger)
	orgID := "org-123"
	ctx := t.Context()
	ctx = cmdctx.WithIctx(ctx, mockIctx)
	ctx = cmdctx.WithConfig(ctx, mockIctx.GetConfiguration())
	ctx = cmdctx.WithLogger(ctx, &logger)
	ctx = cmdctx.WithErrorFactory(ctx, ef)
	ctx = cmdctx.WithProgressBar(ctx, &nopProgressBar)

	_, _, err := ostest.RunUnifiedTestFlow(ctx, ".", mockTestClient, orgID, nil, nil)
	require.NoError(t, err)

	p := peak.Load()
	const limit int32 = 5
	require.LessOrEqualf(t, p, limit, "observed concurrency %d exceeds limit %d", p, limit)
}

// Test_RunUnifiedTestFlow_ConcurrencyLimitHonorsMaxThreads verifies that when MAX_THREADS is set lower than
// the default, it is respected as the upper bound for concurrent tests.
func Test_RunUnifiedTestFlow_ConcurrencyLimitHonorsMaxThreads(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := gafmocks.NewMockEngine(ctrl)
	mockIctx := gafmocks.NewMockInvocationContext(ctrl)

	cfg := configuration.New()
	// Ensure a predictable bound lower than the default 5
	cfg.Set(configuration.MAX_THREADS, 3)
	cfg.Set(ostest.FeatureFlagRiskScore, true)
	cfg.Set(ostest.FeatureFlagRiskScoreInCLI, true)
	cfg.Set(flags.FlagAllProjects, true)

	logger := zerolog.Nop()

	mockIctx.EXPECT().GetConfiguration().Return(cfg).AnyTimes()
	mockIctx.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
	mockIctx.EXPECT().GetRuntimeInfo().Return(runtimeinfo.New()).AnyTimes()
	mockIctx.EXPECT().GetEngine().Return(mockEngine).AnyTimes()
	mockIctx.EXPECT().GetWorkflowIdentifier().Return(common.DepGraphWorkflowID).AnyTimes()

	const n = 10
	depGraphDatas := make([]workflow.Data, 0, n)
	for i := 0; i < n; i++ {
		dg := testapi.IoSnykApiV1testdepgraphRequestDepGraph{
			SchemaVersion: "1.2.0",
			PkgManager:    testapi.IoSnykApiV1testdepgraphRequestPackageManager{Name: "npm"},
			Pkgs: []testapi.IoSnykApiV1testdepgraphRequestPackage{
				{Id: "proj@1.0.0", Info: testapi.IoSnykApiV1testdepgraphRequestPackageInfo{Name: "proj", Version: "1.0.0"}},
			},
			Graph: testapi.IoSnykApiV1testdepgraphRequestGraph{RootNodeId: "root"},
		}
		bytes, err := json.Marshal(dg)
		require.NoError(t, err)
		d := gafmocks.NewMockData(ctrl)
		d.EXPECT().GetPayload().Return(bytes).AnyTimes()
		d.EXPECT().GetMetaData(common.NormalisedTargetFileKey).Return("proj/package.json", nil).AnyTimes()
		d.EXPECT().GetMetaData(common.TargetFileFromPluginKey).Return("proj/package.json", nil).AnyTimes()
		d.EXPECT().GetMetaData(common.TargetKey).Return("{}", nil).AnyTimes()
		depGraphDatas = append(depGraphDatas, d)
	}
	mockEngine.EXPECT().InvokeWithConfig(common.DepGraphWorkflowID, gomock.Any()).Return(depGraphDatas, nil).Times(1)

	var current, peak atomic.Int32
	mockTestClient := mockConcurrentStartTest(ctrl, n, &current, &peak)

	// Run
	ef := errors.NewErrorFactory(&logger)
	orgID := "org-123"
	ctx := t.Context()
	ctx = cmdctx.WithIctx(ctx, mockIctx)
	ctx = cmdctx.WithConfig(ctx, mockIctx.GetConfiguration())
	ctx = cmdctx.WithLogger(ctx, &logger)
	ctx = cmdctx.WithErrorFactory(ctx, ef)
	ctx = cmdctx.WithProgressBar(ctx, &nopProgressBar)

	_, _, err := ostest.RunUnifiedTestFlow(ctx, ".", mockTestClient, orgID, nil, nil)
	require.NoError(t, err)

	p := peak.Load()
	const limit int32 = 3
	require.LessOrEqualf(t, p, limit, "observed concurrency %d exceeds limit %d", p, limit)
}

// Test_RunUnifiedTestFlow_WithIgnorePolicyFlag verifies that the ignore-policy flag
// is correctly added to depgraphs before being sent to the test API.
func Test_RunUnifiedTestFlow_WithIgnorePolicyFlag(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := gafmocks.NewMockEngine(ctrl)
	mockIctx := gafmocks.NewMockInvocationContext(ctrl)

	cfg := configuration.New()
	cfg.Set(ostest.FeatureFlagRiskScore, true)
	cfg.Set(ostest.FeatureFlagRiskScoreInCLI, true)
	cfg.Set(flags.FlagIgnorePolicy, true)

	logger := zerolog.Nop()

	mockIctx.EXPECT().GetConfiguration().Return(cfg).AnyTimes()
	mockIctx.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
	mockIctx.EXPECT().GetRuntimeInfo().Return(runtimeinfo.New()).AnyTimes()
	mockIctx.EXPECT().GetWorkflowIdentifier().Return(common.DepGraphWorkflowID).AnyTimes()
	mockIctx.EXPECT().GetEngine().Return(mockEngine).AnyTimes()

	// Create a single depgraph
	dg := testapi.IoSnykApiV1testdepgraphRequestDepGraph{
		SchemaVersion: "1.2.0",
		PkgManager:    testapi.IoSnykApiV1testdepgraphRequestPackageManager{Name: "npm"},
		Pkgs: []testapi.IoSnykApiV1testdepgraphRequestPackage{
			{Id: "proj@1.0.0", Info: testapi.IoSnykApiV1testdepgraphRequestPackageInfo{Name: "proj", Version: "1.0.0"}},
		},
		Graph: testapi.IoSnykApiV1testdepgraphRequestGraph{RootNodeId: "root"},
	}
	bytes, err := json.Marshal(dg)
	require.NoError(t, err)
	d := gafmocks.NewMockData(ctrl)
	d.EXPECT().GetPayload().Return(bytes).AnyTimes()
	d.EXPECT().GetMetaData(common.NormalisedTargetFileKey).Return("proj/package.json", nil).AnyTimes()
	d.EXPECT().GetMetaData(common.TargetFileFromPluginKey).Return("proj/package.json", nil).AnyTimes()
	d.EXPECT().GetMetaData(common.TargetKey).Return("{}", nil).AnyTimes()

	mockEngine.EXPECT().InvokeWithConfig(common.DepGraphWorkflowID, gomock.Any()).Return([]workflow.Data{d}, nil).Times(1)

	// Mock TestClient to capture the StartTest call and verify the depgraph contains ignorePolicy
	mockTestClient := gafclientmocks.NewMockTestClient(ctrl)
	mockTestClient.EXPECT().StartTest(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, params testapi.StartTestParams) (testapi.TestHandle, error) {
		// Verify the depgraph has the ignorePolicy field set
		subject := params.Subject
		depGraphSubject, dgErr := subject.AsDepGraphSubjectCreate()
		require.NoError(t, dgErr)

		value, exists := depGraphSubject.DepGraph.Get("ignorePolicy")
		require.True(t, exists, "depgraph should have ignorePolicy field set")
		require.Equal(t, true, value, "ignorePolicy should be true")

		// Return a successful test result
		handle := gafclientmocks.NewMockTestHandle(ctrl)
		handle.EXPECT().Wait(gomock.Any()).Return(nil).Times(1)

		result := gafclientmocks.NewMockTestResult(ctrl)
		result.EXPECT().GetExecutionState().Return(testapi.TestExecutionStatesFinished).AnyTimes()
		result.EXPECT().Findings(gomock.Any()).Return([]testapi.FindingData{}, true, nil).AnyTimes()
		handle.EXPECT().Result().Return(result).Times(1)

		return handle, nil
	}).Times(1)

	// Run
	ef := errors.NewErrorFactory(&logger)
	orgID := "org-123"
	ctx := t.Context()
	ctx = cmdctx.WithIctx(ctx, mockIctx)
	ctx = cmdctx.WithConfig(ctx, cfg)
	ctx = cmdctx.WithLogger(ctx, &logger)
	ctx = cmdctx.WithErrorFactory(ctx, ef)
	ctx = cmdctx.WithProgressBar(ctx, &nopProgressBar)

	_, _, err = ostest.RunUnifiedTestFlow(ctx, ".", mockTestClient, orgID, nil, nil)
	require.NoError(t, err)
}

// Test_RunUnifiedTestFlow_WithProjectNameOverride verifies that the project-name flag
// is correctly added to depgraphs as projectNameOverride before being sent to the test API.
func Test_RunUnifiedTestFlow_WithProjectNameOverride(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := gafmocks.NewMockEngine(ctrl)
	mockIctx := gafmocks.NewMockInvocationContext(ctrl)

	cfg := configuration.New()
	cfg.Set(ostest.FeatureFlagRiskScore, true)
	cfg.Set(ostest.FeatureFlagRiskScoreInCLI, true)
	cfg.Set(flags.FlagProjectName, "my-custom-project-name")

	logger := zerolog.Nop()

	mockIctx.EXPECT().GetConfiguration().Return(cfg).AnyTimes()
	mockIctx.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
	mockIctx.EXPECT().GetRuntimeInfo().Return(runtimeinfo.New()).AnyTimes()
	mockIctx.EXPECT().GetWorkflowIdentifier().Return(common.DepGraphWorkflowID).AnyTimes()
	mockIctx.EXPECT().GetEngine().Return(mockEngine).AnyTimes()

	// Create a single depgraph
	dg := testapi.IoSnykApiV1testdepgraphRequestDepGraph{
		SchemaVersion: "1.2.0",
		PkgManager:    testapi.IoSnykApiV1testdepgraphRequestPackageManager{Name: "npm"},
		Pkgs: []testapi.IoSnykApiV1testdepgraphRequestPackage{
			{Id: "proj@1.0.0", Info: testapi.IoSnykApiV1testdepgraphRequestPackageInfo{Name: "proj", Version: "1.0.0"}},
		},
		Graph: testapi.IoSnykApiV1testdepgraphRequestGraph{RootNodeId: "root"},
	}
	bytes, err := json.Marshal(dg)
	require.NoError(t, err)
	d := gafmocks.NewMockData(ctrl)
	d.EXPECT().GetPayload().Return(bytes).AnyTimes()
	d.EXPECT().GetMetaData(common.NormalisedTargetFileKey).Return("proj/package.json", nil).AnyTimes()
	d.EXPECT().GetMetaData(common.TargetFileFromPluginKey).Return("proj/package.json", nil).AnyTimes()
	d.EXPECT().GetMetaData(common.TargetKey).Return("{}", nil).AnyTimes()

	mockEngine.EXPECT().InvokeWithConfig(common.DepGraphWorkflowID, gomock.Any()).Return([]workflow.Data{d}, nil).Times(1)

	// Mock TestClient to capture the StartTest call and verify the depgraph contains projectNameOverride
	mockTestClient := gafclientmocks.NewMockTestClient(ctrl)
	mockTestClient.EXPECT().StartTest(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, params testapi.StartTestParams) (testapi.TestHandle, error) {
		// Verify the depgraph has the projectNameOverride field set
		subject := params.Subject
		depGraphSubject, dgErr := subject.AsDepGraphSubjectCreate()
		require.NoError(t, dgErr)

		value, exists := depGraphSubject.DepGraph.Get("projectNameOverride")
		require.True(t, exists, "depgraph should have projectNameOverride field set")
		require.Equal(t, "my-custom-project-name", value, "projectNameOverride should match the flag value")

		// Return a successful test result
		handle := gafclientmocks.NewMockTestHandle(ctrl)
		handle.EXPECT().Wait(gomock.Any()).Return(nil).Times(1)

		result := gafclientmocks.NewMockTestResult(ctrl)
		result.EXPECT().GetExecutionState().Return(testapi.TestExecutionStatesFinished).AnyTimes()
		result.EXPECT().Findings(gomock.Any()).Return([]testapi.FindingData{}, true, nil).AnyTimes()
		handle.EXPECT().Result().Return(result).Times(1)

		return handle, nil
	}).Times(1)

	// Run
	ef := errors.NewErrorFactory(&logger)
	orgID := "org-123"
	ctx := t.Context()
	ctx = cmdctx.WithIctx(ctx, mockIctx)
	ctx = cmdctx.WithConfig(ctx, cfg)
	ctx = cmdctx.WithLogger(ctx, &logger)
	ctx = cmdctx.WithErrorFactory(ctx, ef)
	ctx = cmdctx.WithProgressBar(ctx, &nopProgressBar)

	_, _, err = ostest.RunUnifiedTestFlow(ctx, ".", mockTestClient, orgID, nil, nil)
	require.NoError(t, err)
}

// Test_RunUnifiedTestFlow_WithTargetReference verifies that the target-reference flag
// is correctly added to depgraphs as targetReference before being sent to the test API.
func Test_RunUnifiedTestFlow_WithTargetReference(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := gafmocks.NewMockEngine(ctrl)
	mockIctx := gafmocks.NewMockInvocationContext(ctrl)

	cfg := configuration.New()
	cfg.Set(ostest.FeatureFlagRiskScore, true)
	cfg.Set(ostest.FeatureFlagRiskScoreInCLI, true)
	cfg.Set(flags.FlagTargetReference, "feature-branch-123")

	logger := zerolog.Nop()

	mockIctx.EXPECT().GetConfiguration().Return(cfg).AnyTimes()
	mockIctx.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
	mockIctx.EXPECT().GetRuntimeInfo().Return(runtimeinfo.New()).AnyTimes()
	mockIctx.EXPECT().GetWorkflowIdentifier().Return(common.DepGraphWorkflowID).AnyTimes()
	mockIctx.EXPECT().GetEngine().Return(mockEngine).AnyTimes()

	// Create a single depgraph
	dg := testapi.IoSnykApiV1testdepgraphRequestDepGraph{
		SchemaVersion: "1.2.0",
		PkgManager:    testapi.IoSnykApiV1testdepgraphRequestPackageManager{Name: "npm"},
		Pkgs: []testapi.IoSnykApiV1testdepgraphRequestPackage{
			{Id: "proj@1.0.0", Info: testapi.IoSnykApiV1testdepgraphRequestPackageInfo{Name: "proj", Version: "1.0.0"}},
		},
		Graph: testapi.IoSnykApiV1testdepgraphRequestGraph{RootNodeId: "root"},
	}
	bytes, err := json.Marshal(dg)
	require.NoError(t, err)
	d := gafmocks.NewMockData(ctrl)
	d.EXPECT().GetPayload().Return(bytes).AnyTimes()
	d.EXPECT().GetMetaData(common.NormalisedTargetFileKey).Return("proj/package.json", nil).AnyTimes()
	d.EXPECT().GetMetaData(common.TargetFileFromPluginKey).Return("proj/package.json", nil).AnyTimes()
	d.EXPECT().GetMetaData(common.TargetKey).Return("{}", nil).AnyTimes()

	mockEngine.EXPECT().InvokeWithConfig(common.DepGraphWorkflowID, gomock.Any()).Return([]workflow.Data{d}, nil).Times(1)

	// Mock TestClient to capture the StartTest call and verify the depgraph contains targetReference
	mockTestClient := gafclientmocks.NewMockTestClient(ctrl)
	mockTestClient.EXPECT().StartTest(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, params testapi.StartTestParams) (testapi.TestHandle, error) {
		// Verify the depgraph has the targetReference field set
		subject := params.Subject
		depGraphSubject, dgErr := subject.AsDepGraphSubjectCreate()
		require.NoError(t, dgErr)

		value, exists := depGraphSubject.DepGraph.Get("targetReference")
		require.True(t, exists, "depgraph should have targetReference field set")
		require.Equal(t, "feature-branch-123", value, "targetReference should match the flag value")

		// Return a successful test result
		handle := gafclientmocks.NewMockTestHandle(ctrl)
		handle.EXPECT().Wait(gomock.Any()).Return(nil).Times(1)

		result := gafclientmocks.NewMockTestResult(ctrl)
		result.EXPECT().GetExecutionState().Return(testapi.TestExecutionStatesFinished).AnyTimes()
		result.EXPECT().Findings(gomock.Any()).Return([]testapi.FindingData{}, true, nil).AnyTimes()
		handle.EXPECT().Result().Return(result).Times(1)

		return handle, nil
	}).Times(1)

	// Run
	ef := errors.NewErrorFactory(&logger)
	orgID := "org-123"
	ctx := t.Context()
	ctx = cmdctx.WithIctx(ctx, mockIctx)
	ctx = cmdctx.WithConfig(ctx, cfg)
	ctx = cmdctx.WithLogger(ctx, &logger)
	ctx = cmdctx.WithErrorFactory(ctx, ef)
	ctx = cmdctx.WithProgressBar(ctx, &nopProgressBar)

	_, _, err = ostest.RunUnifiedTestFlow(ctx, ".", mockTestClient, orgID, nil, nil)
	require.NoError(t, err)
}

// Test_RunUnifiedTestFlow_CancelsOnError verifies that an error from one depgraph
// cancels siblings via the errgroup context and raises the error.
func Test_RunUnifiedTestFlow_CancelsOnError(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := gafmocks.NewMockEngine(ctrl)
	mockIctx := gafmocks.NewMockInvocationContext(ctrl)

	cfg := configuration.New()
	cfg.Set(ostest.FeatureFlagRiskScore, true)
	cfg.Set(ostest.FeatureFlagRiskScoreInCLI, true)
	cfg.Set(flags.FlagAllProjects, true)

	logger := zerolog.Nop()

	mockIctx.EXPECT().GetConfiguration().Return(cfg).AnyTimes()
	mockIctx.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
	mockIctx.EXPECT().GetRuntimeInfo().Return(runtimeinfo.New()).AnyTimes()
	mockIctx.EXPECT().GetEngine().Return(mockEngine).AnyTimes()

	const n = 6
	depGraphDatas := make([]workflow.Data, 0, n)
	for i := 0; i < n; i++ {
		dg := testapi.IoSnykApiV1testdepgraphRequestDepGraph{
			SchemaVersion: "1.2.0",
			PkgManager:    testapi.IoSnykApiV1testdepgraphRequestPackageManager{Name: "npm"},
			Pkgs: []testapi.IoSnykApiV1testdepgraphRequestPackage{
				{Id: "proj@1.0.0", Info: testapi.IoSnykApiV1testdepgraphRequestPackageInfo{Name: "proj", Version: "1.0.0"}},
			},
			Graph: testapi.IoSnykApiV1testdepgraphRequestGraph{RootNodeId: "root"},
		}
		bytes, err := json.Marshal(dg)
		require.NoError(t, err)
		d := gafmocks.NewMockData(ctrl)
		d.EXPECT().GetPayload().Return(bytes).AnyTimes()
		d.EXPECT().GetMetaData(common.NormalisedTargetFileKey).Return("proj/package.json", nil).AnyTimes()
		d.EXPECT().GetMetaData(common.TargetFileFromPluginKey).Return("proj/package.json", nil).AnyTimes()
		d.EXPECT().GetMetaData(common.TargetKey).Return("{}", nil).AnyTimes()
		depGraphDatas = append(depGraphDatas, d)
	}
	mockEngine.EXPECT().InvokeWithConfig(common.DepGraphWorkflowID, gomock.Any()).Return(depGraphDatas, nil).Times(1)

	// Mock TestClient where first Wait errors, others are canceled.
	var canceledCount atomic.Int32
	var callIndex atomic.Int32
	mockTestClient := gafclientmocks.NewMockTestClient(ctrl)
	mockTestClient.EXPECT().StartTest(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, _ testapi.StartTestParams) (testapi.TestHandle, error) {
		idx := callIndex.Add(1)
		handle := gafclientmocks.NewMockTestHandle(ctrl)
		handle.EXPECT().Wait(gomock.Any()).DoAndReturn(func(wctx context.Context) error {
			if idx == 1 {
				// Trigger group error immediately
				return fmt.Errorf("forced error")
			}
			select {
			case <-wctx.Done():
				canceledCount.Add(1)
				return wctx.Err()
			case <-time.After(2 * time.Second):
				// Fallback to avoid hanging tests
				return nil
			}
		}).Times(1)
		return handle, nil
	}).Times(n)

	// Run with a timeout to avoid hanging in case of failure.
	runCtx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	ef := errors.NewErrorFactory(&logger)
	ctx := runCtx
	ctx = cmdctx.WithIctx(ctx, mockIctx)
	ctx = cmdctx.WithConfig(ctx, mockIctx.GetConfiguration())
	ctx = cmdctx.WithLogger(ctx, &logger)
	ctx = cmdctx.WithErrorFactory(ctx, ef)
	ctx = cmdctx.WithProgressBar(ctx, &nopProgressBar)

	_, _, err := ostest.RunUnifiedTestFlow(ctx, ".", mockTestClient, "org-123", nil, nil)
	require.Error(t, err)

	// At least one sibling should have observed cancellation.
	if canceledCount.Load() == 0 {
		count := canceledCount.Load()
		t.Fatalf("expected at least one canceled sibling, got %d", count)
	}
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
