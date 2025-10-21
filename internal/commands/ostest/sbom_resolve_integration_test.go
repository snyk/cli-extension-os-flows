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

// TestSBOMResolveIntegration_DepGraphsPassedToUnifiedTestAPI verifies that when the UV test flow
// is enabled, dep-graphs from SBOM resolution are properly passed to the Unified Test API.
func TestSBOMResolveIntegration_DepGraphsPassedToUnifiedTestAPI(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	mockIctx, mockTestClient, mockDepGraph, orgID, cfg, testLogger := setupSBOMResolveIntegrationTest(t, ctrl)

	// Set up context with dependencies
	testErrFactory := errors.NewErrorFactory(testLogger)
	nopProgressBar := &NopProgressBar{}
	ctx = cmdctx.WithIctx(ctx, mockIctx)
	ctx = cmdctx.WithConfig(ctx, cfg)
	ctx = cmdctx.WithLogger(ctx, testLogger)
	ctx = cmdctx.WithErrorFactory(ctx, testErrFactory)
	ctx = cmdctx.WithProgressBar(ctx, nopProgressBar)

	_, _, err := ostest.RunUnifiedTestFlow(
		ctx,
		".",
		mockTestClient,
		orgID,
		nil,
		nil,
	)

	require.NoError(t, err)
	require.NotNil(t, mockDepGraph)
}

//nolint:gocritic // Test helper needs to return multiple values for test setup
func setupSBOMResolveIntegrationTest(
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

	nopLogger := zerolog.Nop()

	mockIctx.EXPECT().GetConfiguration().Return(cfg).AnyTimes()
	mockIctx.EXPECT().GetEnhancedLogger().Return(&nopLogger).AnyTimes()
	mockIctx.EXPECT().GetRuntimeInfo().Return(runtimeinfo.New()).AnyTimes()
	mockIctx.EXPECT().GetEngine().Return(mockEngine).AnyTimes()
	mockIctx.EXPECT().GetWorkflowIdentifier().Return(workflow.NewWorkflowIdentifier("test")).AnyTimes()

	depGraphBytes, err := os.ReadFile("testdata/uv_depgraph.json")
	require.NoError(t, err)

	var mockDepGraph testapi.IoSnykApiV1testdepgraphRequestDepGraph
	require.NoError(t, json.Unmarshal(depGraphBytes, &mockDepGraph))

	depGraphData := workflow.NewData(
		workflow.NewTypeIdentifier(common.DepGraphWorkflowID, "depgraph"),
		"application/json",
		depGraphBytes,
	)
	depGraphData.SetMetaData("Content-Location", "uv.lock")

	mockEngine.EXPECT().
		InvokeWithConfig(common.DepGraphWorkflowID, gomock.Any()).
		DoAndReturn(func(_ workflow.Identifier, cfg configuration.Configuration) ([]workflow.Data, error) {
			// Verify that use-sbom-resolve flag is set
			assert.True(t, cfg.GetBool("use-sbom-resolve"), "use-sbom-resolve flag should be set when UV support is enabled")
			return []workflow.Data{depGraphData}, nil
		}).
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

	return mockIctx, mockTestClient, &mockDepGraph, "test-org-id", cfg, &nopLogger
}
