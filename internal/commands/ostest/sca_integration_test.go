package ostest_test

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	gafclientmocks "github.com/snyk/go-application-framework/pkg/apiclients/mocks"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	gafmocks "github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	"github.com/snyk/cli-extension-os-flows/internal/commands/ostest"
	common "github.com/snyk/cli-extension-os-flows/internal/common"
	"github.com/snyk/cli-extension-os-flows/internal/errors"
	"github.com/snyk/cli-extension-os-flows/internal/flags"
)

// TestSCAIntegration_DepGraphsPassedToUnifiedTestAPI verifies that when the UV test flow
// is enabled, dep-graphs from the SCA extension are properly passed to the Unified Test API.
func TestSCAIntegration_DepGraphsPassedToUnifiedTestAPI(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	mockIctx, mockTestClient, mockDepGraph, orgID, cfg, logger := setupSCAIntegrationTest(t, ctrl)

	// Set up context with dependencies
	errFactory := errors.NewErrorFactory(logger)
	nopProgressBar := &NopProgressBar{}
	ctx = cmdctx.WithIctx(ctx, mockIctx)
	ctx = cmdctx.WithConfig(ctx, cfg)
	ctx = cmdctx.WithLogger(ctx, logger)
	ctx = cmdctx.WithErrorFactory(ctx, errFactory)
	ctx = cmdctx.WithProgressBar(ctx, nopProgressBar)

	_, err := ostest.RunUnifiedTestFlow(
		ctx,
		mockTestClient,
		orgID,
		nil,
		nil,
	)

	require.NoError(t, err)
	require.NotNil(t, mockDepGraph)
}

func setupSCAIntegrationTest(
	t *testing.T,
	ctrl *gomock.Controller,
) (
	workflow.InvocationContext,
	testapi.TestClient,
	*testapi.IoSnykApiV1testdepgraphRequestDepGraph,
	string,
	configuration.Configuration,
	*zerolog.Logger,
) {
	t.Helper()

	mockEngine := gafmocks.NewMockEngine(ctrl)
	mockIctx := gafmocks.NewMockInvocationContext(ctrl)
	mockTestClient := gafclientmocks.NewMockTestClient(ctrl)

	cfg := configuration.New()
	cfg.Set(ostest.EnableExperimentalUvSupportEnvVar, true)
	cfg.Set(configuration.ORGANIZATION, "test-org-id")
	cfg.Set(flags.FlagFile, "uv.lock")

	logger := zerolog.Nop()

	mockIctx.EXPECT().GetConfiguration().Return(cfg).AnyTimes()
	mockIctx.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
	mockIctx.EXPECT().GetRuntimeInfo().Return(runtimeinfo.New()).AnyTimes()
	mockIctx.EXPECT().GetEngine().Return(mockEngine).AnyTimes()
	mockIctx.EXPECT().GetWorkflowIdentifier().Return(workflow.NewWorkflowIdentifier("test")).AnyTimes()

	depGraphBytes, err := os.ReadFile("testdata/uv_depgraph.json")
	require.NoError(t, err)

	var mockDepGraph testapi.IoSnykApiV1testdepgraphRequestDepGraph
	require.NoError(t, json.Unmarshal(depGraphBytes, &mockDepGraph))

	scaData := workflow.NewData(
		workflow.NewTypeIdentifier(common.SCAWorkflowID, "depgraph"),
		"application/json",
		depGraphBytes,
	)
	scaData.SetMetaData("Content-Location", "uv.lock")

	mockEngine.EXPECT().
		InvokeWithConfig(common.SCAWorkflowID, gomock.Any()).
		Return([]workflow.Data{scaData}, nil).
		Times(1)

	mockTestClient.EXPECT().
		StartTest(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, params testapi.StartTestParams) (testapi.TestHandle, error) {
			require.NotNil(t, params.Subject)

			depGraphSubject, subjectErr := params.Subject.AsDepGraphSubjectCreate()
			require.NoError(t, subjectErr)

			assert.Equal(t, mockDepGraph, depGraphSubject.DepGraph)

			handle := gafclientmocks.NewMockTestHandle(ctrl)
			handle.EXPECT().Wait(gomock.Any()).Return(nil).Times(1)

			result := gafclientmocks.NewMockTestResult(ctrl)
			result.EXPECT().GetExecutionState().Return(testapi.TestExecutionStatesFinished).AnyTimes()
			result.EXPECT().Findings(gomock.Any()).Return([]testapi.FindingData{}, true, nil).AnyTimes()
			handle.EXPECT().Result().Return(result).Times(1)

			return handle, nil
		}).
		Times(1)

	return mockIctx, mockTestClient, &mockDepGraph, "test-org-id", cfg, &logger
}
