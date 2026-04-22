package osmonitor_test

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/snyk/go-application-framework/pkg/apiclients/fileupload"
	gafclientmocks "github.com/snyk/go-application-framework/pkg/apiclients/mocks"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/commands/osmonitor"
	"github.com/snyk/cli-extension-os-flows/internal/commands/ostest"
	"github.com/snyk/cli-extension-os-flows/internal/common"
	"github.com/snyk/cli-extension-os-flows/internal/constants"
	"github.com/snyk/cli-extension-os-flows/internal/util"
	"github.com/snyk/cli-extension-os-flows/pkg/flags"
)

func Test_RunDflyMonitorFlow_JSON(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx, orgID, _ := setupDflyTestFixture(t, ctrl)
	mockTestClient := setupMockTestClient(t, ctrl)
	ffc := fileupload.NewFakeClient()
	fdr := newSinglePkgDepgraphResolver()

	_, wfData, err := common.RunDflyDepgraphFlow(
		ctx, ".", fdr,
		common.FlowClients{FileUploadClient: ffc, TestClient: mockTestClient},
		orgID, nil, nil, util.Ptr(true),
		ostest.RunTestWithResources,
	)
	require.NoError(t, err)

	assert.Equal(t, 1, ffc.GetUploadCount())
	require.NotEmpty(t, wfData)
}

func Test_RunDflyMonitorFlow_PublishReportIsSet(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx, orgID, _ := setupDflyTestFixture(t, ctrl)
	mockTestClient, getCapturedConfig := setupCapturingTestClient(ctrl)
	ffc := fileupload.NewFakeClient()
	fdr := newSinglePkgDepgraphResolver()

	_, _, err := common.RunDflyDepgraphFlow(
		ctx, ".", fdr,
		common.FlowClients{FileUploadClient: ffc, TestClient: mockTestClient},
		orgID, nil, nil, util.Ptr(true),
		ostest.RunTestWithResources,
	)
	require.NoError(t, err)

	capturedConfig := getCapturedConfig()
	require.NotNil(t, capturedConfig)
	require.NotNil(t, capturedConfig.PublishReport)
	assert.True(t, *capturedConfig.PublishReport)
}

func Test_RunDflyMonitorFlow_ProjectMetadataForwarded(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx, orgID, cfg := setupDflyTestFixture(t, ctrl)
	cfg.Set(flags.FlagTargetReference, "main")
	cfg.Set(flags.FlagProjectBusinessCriticality, "high")
	cfg.Set(flags.FlagProjectEnvironment, "frontend,backend")
	cfg.Set(flags.FlagProjectLifecycle, "production")
	cfg.Set(flags.FlagProjectTags, "dept=engineering,team=cli")

	mockTestClient, getCapturedConfig := setupCapturingTestClient(ctrl)
	ffc := fileupload.NewFakeClient()
	fdr := newSinglePkgDepgraphResolver()

	_, _, err := common.RunDflyDepgraphFlow(
		ctx, ".", fdr,
		common.FlowClients{FileUploadClient: ffc, TestClient: mockTestClient},
		orgID, nil, nil, util.Ptr(true),
		ostest.RunTestWithResources,
	)
	require.NoError(t, err)

	capturedConfig := getCapturedConfig()
	require.NotNil(t, capturedConfig)
	require.NotNil(t, capturedConfig.TargetReference)
	assert.Equal(t, "main", *capturedConfig.TargetReference)
	require.NotNil(t, capturedConfig.ProjectBusinessCriticality)
	assert.Equal(t, "high", *capturedConfig.ProjectBusinessCriticality)
	require.NotNil(t, capturedConfig.ProjectEnvironment)
	assert.Equal(t, []string{"frontend", "backend"}, *capturedConfig.ProjectEnvironment)
	require.NotNil(t, capturedConfig.ProjectLifecycle)
	assert.Equal(t, []string{"production"}, *capturedConfig.ProjectLifecycle)
	require.NotNil(t, capturedConfig.ProjectTags)
	assert.Equal(t, []string{"dept=engineering", "team=cli"}, *capturedConfig.ProjectTags)
}

func Test_RunDflyMonitorFlow_UploadFailure(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx, orgID, _ := setupDflyTestFixture(t, ctrl)
	mockTestClient := gafclientmocks.NewMockTestClient(ctrl)
	ffc := fileupload.NewFakeClient()
	ffc.WithError(assert.AnError)
	fdr := newSinglePkgDepgraphResolver()

	_, _, err := common.RunDflyDepgraphFlow(
		ctx, ".", fdr,
		common.FlowClients{FileUploadClient: ffc, TestClient: mockTestClient},
		orgID, nil, nil, util.Ptr(true),
		ostest.RunTestWithResources,
	)
	assert.ErrorContains(t, err, "failed to upload dependency graphs")
}

func Test_OSWorkflow_DflyFFEnabled_UsesDflyFlow(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := createMockEngine(ctrl)
	// Allow any engine invocations (dep-graph resolver calls engine internally)
	mockEngine.EXPECT().InvokeWithConfig(gomock.Any(), gomock.Any()).Return(nil, nil).AnyTimes()

	mockIctx := createMockInvocationCtxWithURL(t, ctrl, mockEngine)
	cfg := mockIctx.GetConfiguration()
	cfg.Set(constants.FeatureFlagDlfyCLIRollout, true)
	cfg.Set(configuration.INPUT_DIRECTORY, t.TempDir())
	cfg.Set(configuration.RAW_CMD_ARGS, "monitor "+t.TempDir())

	// The dfly flow will fail trying to resolve dep graphs since there's no real project,
	// but that's expected -- we're verifying routing, not the full flow.
	_, err := osmonitor.OSWorkflow(mockIctx, []workflow.Data{})

	// We should get an error from the dfly path (not a legacy invocation).
	assert.Error(t, err)
}

func Test_OSWorkflow_DflyFFDisabled_UsesLegacy(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	legacyWorkflowID := workflow.NewWorkflowIdentifier("legacycli")
	mockEngine := createMockEngine(ctrl)
	mockEngine.EXPECT().
		InvokeWithConfig(legacyWorkflowID, gomock.Any()).
		Return([]workflow.Data{}, nil).
		Times(1)

	mockIctx := createMockInvocationCtxWithURL(t, ctrl, mockEngine)
	cfg := mockIctx.GetConfiguration()
	cfg.Set(constants.FeatureFlagDlfyCLIRollout, false)

	result, err := osmonitor.OSWorkflow(mockIctx, []workflow.Data{})
	assert.NoError(t, err)
	assert.NotNil(t, result)
}

func Test_OSWorkflow_ForceLegacy_OverridesDflyFF(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	legacyWorkflowID := workflow.NewWorkflowIdentifier("legacycli")
	mockEngine := createMockEngine(ctrl)
	mockEngine.EXPECT().
		InvokeWithConfig(legacyWorkflowID, gomock.Any()).
		Return([]workflow.Data{}, nil).
		Times(1)

	mockIctx := createMockInvocationCtxWithURL(t, ctrl, mockEngine)
	cfg := mockIctx.GetConfiguration()
	cfg.Set(constants.FeatureFlagDlfyCLIRollout, true)
	cfg.Set(constants.ForceLegacyCLIEnvVar, true)

	result, err := osmonitor.OSWorkflow(mockIctx, []workflow.Data{})
	assert.NoError(t, err)
	assert.NotNil(t, result)
}
