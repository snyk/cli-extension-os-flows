package osmonitor_test

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/snyk/go-application-framework/pkg/apiclients/fileupload"
	gafclientmocks "github.com/snyk/go-application-framework/pkg/apiclients/mocks"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/content_type"
	"github.com/snyk/go-application-framework/pkg/utils/ufm"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/commands/osmonitor"
	"github.com/snyk/cli-extension-os-flows/internal/commands/ostest"
	"github.com/snyk/cli-extension-os-flows/internal/common"
	"github.com/snyk/cli-extension-os-flows/internal/constants"
	"github.com/snyk/cli-extension-os-flows/pkg/flags"
)

func Test_RunDflyMonitorFlow_JSON(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx, orgID, cfg := setupDflyTestFixture(t, ctrl)
	cfg.Set(flags.FlagMonitor, true)
	mockTestClient := setupMockTestClient(t, ctrl)
	ffc := fileupload.NewFakeClient()
	fdr := newSinglePkgDepgraphResolver()

	_, wfData, err := common.RunDflyDepgraphFlow(
		ctx, ".", fdr,
		common.FlowClients{FileUploadClient: ffc, TestClient: mockTestClient},
		orgID, nil, nil,
		ostest.RunTestWithResources,
	)
	require.NoError(t, err)

	assert.Equal(t, 1, ffc.GetUploadCount())
	require.NotEmpty(t, wfData)
}

func Test_RunDflyMonitorFlow_MonitorIsSet(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx, orgID, cfg := setupDflyTestFixture(t, ctrl)
	cfg.Set(flags.FlagMonitor, true)
	mockTestClient, getCapturedConfig := setupCapturingTestClient(ctrl)
	ffc := fileupload.NewFakeClient()
	fdr := newSinglePkgDepgraphResolver()

	_, _, err := common.RunDflyDepgraphFlow(
		ctx, ".", fdr,
		common.FlowClients{FileUploadClient: ffc, TestClient: mockTestClient},
		orgID, nil, nil,
		ostest.RunTestWithResources,
	)
	require.NoError(t, err)

	capturedConfig := getCapturedConfig()
	require.NotNil(t, capturedConfig)
	require.NotNil(t, capturedConfig.Monitor)
	assert.True(t, *capturedConfig.Monitor)
	assert.Nil(t, capturedConfig.PublishReport, "the monitor command sets --monitor, not --report")
}

func Test_RunDflyMonitorFlow_ProjectMetadataForwarded(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx, orgID, cfg := setupDflyTestFixture(t, ctrl)
	cfg.Set(flags.FlagMonitor, true)
	cfg.Set(flags.FlagTargetReference, "main")
	cfg.Set(flags.FlagAssetName, "my-target")
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
		orgID, nil, nil,
		ostest.RunTestWithResources,
	)
	require.NoError(t, err)

	capturedConfig := getCapturedConfig()
	require.NotNil(t, capturedConfig)
	require.NotNil(t, capturedConfig.TargetReference)
	assert.Equal(t, "main", *capturedConfig.TargetReference)
	require.NotNil(t, capturedConfig.AssetName)
	assert.Equal(t, "my-target", *capturedConfig.AssetName)
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

	ctx, orgID, cfg := setupDflyTestFixture(t, ctrl)
	cfg.Set(flags.FlagMonitor, true)
	mockTestClient := gafclientmocks.NewMockTestClient(ctrl)
	ffc := fileupload.NewFakeClient()
	ffc.WithError(assert.AnError)
	fdr := newSinglePkgDepgraphResolver()

	_, _, err := common.RunDflyDepgraphFlow(
		ctx, ".", fdr,
		common.FlowClients{FileUploadClient: ffc, TestClient: mockTestClient},
		orgID, nil, nil,
		ostest.RunTestWithResources,
	)
	assert.ErrorContains(t, err, "failed to upload dependency graphs")
}

func Test_RunDflyMonitorFlow_PrintsLegacyMonitorOutputPerProject(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx, orgID, cfg := setupDflyTestFixture(t, ctrl)
	cfg.Set(configuration.WEB_APP_URL, "https://app.snyk.io")
	inputDir := t.TempDir()
	frontendID, backendID := uuid.New(), uuid.New()
	mockTestClient := setupMockTestClientWithComponents(ctrl, testapi.Pass, []testapi.TestComponent{
		{Key: "gomodules:go.mod", ProjectId: &backendID, ScanType: testapi.FindingTypeSca},
		{Key: "npm:frontend", ProjectId: &frontendID, ScanType: testapi.FindingTypeSca},
	})
	fdr := common.NewFakeDepgraphResolver([]common.DepgraphWithIdentity{
		newDepgraphWithIdentity(common.Identity{Type: "npm", Name: "frontend"}),
		newDepgraphWithIdentity(common.Identity{Type: "gomodules", Name: "backend", TargetFile: "go.mod"}),
	}, nil)

	wfData, err := osmonitor.RunDflyMonitorFlow(
		ctx, []string{inputDir}, orgID,
		common.FlowClients{FileUploadClient: fileupload.NewFakeClient(), TestClient: mockTestClient},
		fdr,
	)
	require.NoError(t, err)

	require.Len(t, wfData, 1)
	assert.Equal(t, "text/plain", wfData[0].GetContentType())
	assert.Equal(t,
		"\nMonitoring "+inputDir+" (frontend)...\n\n"+
			"Explore this snapshot at https://app.snyk.io/org/some-org/project/"+frontendID.String()+"\n\n"+
			"Notifications about newly disclosed issues related to these dependencies will be emailed to you.\n"+
			"\n\n-------------------------------------------------------\n"+
			"\nMonitoring "+inputDir+" (backend)...\n\n"+
			"Explore this snapshot at https://app.snyk.io/org/some-org/project/"+backendID.String()+"\n\n"+
			"Notifications about newly disclosed issues related to these dependencies will be emailed to you.\n",
		string(wfData[0].GetPayload().([]byte)),
	)
}

func Test_RunDflyMonitorFlow_WhenProjectHasNoProjectID_ThenOmitsTheSnapshotLink(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx, orgID, _ := setupDflyTestFixture(t, ctrl)
	inputDir := t.TempDir()
	mockTestClient := setupMockTestClientWithComponents(ctrl, testapi.Pass, nil)
	fdr := common.NewFakeDepgraphResolver([]common.DepgraphWithIdentity{
		newDepgraphWithIdentity(common.Identity{Type: "npm", Name: "frontend"}),
	}, nil)

	wfData, err := osmonitor.RunDflyMonitorFlow(
		ctx, []string{inputDir}, orgID,
		common.FlowClients{FileUploadClient: fileupload.NewFakeClient(), TestClient: mockTestClient},
		fdr,
	)
	require.NoError(t, err)

	require.Len(t, wfData, 1)
	assert.Equal(t,
		"\nMonitoring "+inputDir+" (frontend)...\n\n"+
			"Notifications about newly disclosed issues related to these dependencies will be emailed to you.\n",
		string(wfData[0].GetPayload().([]byte)),
	)
}

func Test_RunDflyMonitorFlow_WhenTestFails_ThenReturnsNoDataThatSetsAFailingExitCode(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx, orgID, _ := setupDflyTestFixture(t, ctrl)
	projectID := uuid.New()
	mockTestClient := setupMockTestClientWithComponents(ctrl, testapi.Fail, []testapi.TestComponent{
		{Key: "npm:frontend", ProjectId: &projectID, ScanType: testapi.FindingTypeSca},
	})
	fdr := common.NewFakeDepgraphResolver([]common.DepgraphWithIdentity{
		newDepgraphWithIdentity(common.Identity{Type: "npm", Name: "frontend"}),
	}, nil)

	wfData, err := osmonitor.RunDflyMonitorFlow(
		ctx, []string{t.TempDir()}, orgID,
		common.FlowClients{FileUploadClient: fileupload.NewFakeClient(), TestClient: mockTestClient},
		fdr,
	)
	require.NoError(t, err)

	for _, d := range wfData {
		assert.Empty(t, ufm.GetTestResultsFromWorkflowData(d), "test results decide the exit code")
		assert.NotEqual(t, content_type.TEST_SUMMARY, d.GetContentType(), "a test summary decides the exit code")
	}
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
	inputDir := initGitRepo(t, "https://github.com/acme/repo.git")
	cfg.Set(configuration.INPUT_DIRECTORY, inputDir)
	cfg.Set(configuration.RAW_CMD_ARGS, "monitor "+inputDir)

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

func Test_OSWorkflow_DflyFF_FlagsOnlyLegacySupports_UseLegacy(t *testing.T) {
	for _, flag := range []string{flags.FlagDocker, flags.FlagContainer, flags.FlagUnmanaged, flags.FlagPrintDeps, flags.FlagPrintDepPaths} {
		t.Run("--"+flag, func(t *testing.T) {
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
			cfg.Set(flag, true)

			result, err := osmonitor.OSWorkflow(mockIctx, []workflow.Data{})
			require.NoError(t, err)
			assert.NotNil(t, result)
		})
	}
}

func Test_OSWorkflow_DflyFF_NoGitRemote_UsesLegacy(t *testing.T) {
	tests := map[string]func(t *testing.T) []string{
		"not a git repository": func(t *testing.T) []string {
			t.Helper()
			return []string{t.TempDir()}
		},
		"git repository without a remote": func(t *testing.T) []string {
			t.Helper()
			return []string{initGitRepo(t, "")}
		},
		"one of several input dirs without a remote": func(t *testing.T) []string {
			t.Helper()
			return []string{initGitRepo(t, "https://github.com/acme/repo.git"), t.TempDir()}
		},
	}

	for name, inputDirs := range tests {
		t.Run(name, func(t *testing.T) {
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
			cfg.Set(configuration.INPUT_DIRECTORY, inputDirs(t))

			result, err := osmonitor.OSWorkflow(mockIctx, []workflow.Data{})
			require.NoError(t, err)
			assert.NotNil(t, result)
		})
	}
}

func Test_OSWorkflow_DflyFF_RemoteRepoURLFlag_UsesDflyFlow(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := createMockEngine(ctrl)
	mockEngine.EXPECT().InvokeWithConfig(gomock.Any(), gomock.Any()).Return(nil, nil).AnyTimes()

	mockIctx := createMockInvocationCtxWithURL(t, ctrl, mockEngine)
	cfg := mockIctx.GetConfiguration()
	cfg.Set(constants.FeatureFlagDlfyCLIRollout, true)
	inputDir := t.TempDir()
	cfg.Set(configuration.INPUT_DIRECTORY, inputDir)
	cfg.Set(configuration.RAW_CMD_ARGS, "monitor "+inputDir)
	cfg.Set(flags.FlagRemoteRepoURL, "https://github.com/acme/repo.git")

	// --remote-repo-url supplies the SCM context, so the dfly flow runs (and fails on the empty project).
	_, err := osmonitor.OSWorkflow(mockIctx, []workflow.Data{})
	assert.Error(t, err)
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
