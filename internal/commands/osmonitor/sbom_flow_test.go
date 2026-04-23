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
	"github.com/snyk/cli-extension-os-flows/internal/common"
	"github.com/snyk/cli-extension-os-flows/internal/constants"
	"github.com/snyk/cli-extension-os-flows/pkg/flags"
)

func Test_RunSbomMonitorFlow_UploadsAndRunsTest(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx, orgID, _ := setupDflyTestFixture(t, ctrl)
	mockTestClient := setupMockTestClient(t, ctrl)
	ffc := fileupload.NewFakeClient()

	clients := common.FlowClients{
		FileUploadClient: ffc,
		TestClient:       mockTestClient,
	}

	wfData, err := osmonitor.RunSbomMonitorFlow(ctx, clients, "testdata/bom.json", orgID)
	require.NoError(t, err)
	require.NotNil(t, wfData)
	assert.Equal(t, 1, ffc.GetUploadCount())
}

func Test_RunSbomMonitorFlow_PublishReportIsTrue(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx, orgID, _ := setupDflyTestFixture(t, ctrl)
	mockTestClient, getCapturedConfig := setupCapturingTestClient(ctrl)
	ffc := fileupload.NewFakeClient()

	clients := common.FlowClients{
		FileUploadClient: ffc,
		TestClient:       mockTestClient,
	}

	_, err := osmonitor.RunSbomMonitorFlow(ctx, clients, "testdata/bom.json", orgID)
	require.NoError(t, err)

	capturedConfig := getCapturedConfig()
	require.NotNil(t, capturedConfig)
	require.NotNil(t, capturedConfig.PublishReport)
	assert.True(t, *capturedConfig.PublishReport)
}

func Test_RunSbomMonitorFlow_ProjectMetadataForwarded(t *testing.T) {
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

	clients := common.FlowClients{
		FileUploadClient: ffc,
		TestClient:       mockTestClient,
	}

	_, err := osmonitor.RunSbomMonitorFlow(ctx, clients, "testdata/bom.json", orgID)
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

func Test_RunSbomMonitorFlow_SCMContext_RemoteRepoURLFlag(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx, orgID, cfg := setupDflyTestFixture(t, ctrl)
	cfg.Set(flags.FlagRemoteRepoURL, "https://github.com/example/repo.git")

	mockTestClient, _, getCapturedResources := setupCapturingTestClientWithResources(ctrl)
	ffc := fileupload.NewFakeClient()

	clients := common.FlowClients{
		FileUploadClient: ffc,
		TestClient:       mockTestClient,
	}

	_, err := osmonitor.RunSbomMonitorFlow(ctx, clients, "testdata/bom.json", orgID)
	require.NoError(t, err)

	capturedResources := getCapturedResources()
	require.NotNil(t, capturedResources)
	require.Len(t, *capturedResources, 1)

	resource := (*capturedResources)[0]
	baseResource, err := resource.AsBaseResourceCreateItem()
	require.NoError(t, err)
	uploadResource, err := baseResource.Resource.AsUploadResource()
	require.NoError(t, err)

	require.NotNil(t, uploadResource.ScmContext, "SCM context should be set when --remote-repo-url is provided")
	require.NotNil(t, uploadResource.ScmContext.RepoUrl)
	assert.Equal(t, "https://github.com/example/repo.git", *uploadResource.ScmContext.RepoUrl)
}

func Test_RunSbomMonitorFlow_UploadFailure(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx, orgID, _ := setupDflyTestFixture(t, ctrl)
	mockTestClient := gafclientmocks.NewMockTestClient(ctrl)
	ffc := fileupload.NewFakeClient()
	ffc.WithError(assert.AnError)

	clients := common.FlowClients{
		FileUploadClient: ffc,
		TestClient:       mockTestClient,
	}

	_, err := osmonitor.RunSbomMonitorFlow(ctx, clients, "testdata/bom.json", orgID)
	assert.ErrorContains(t, err, "failed to upload SBOM")
}

func Test_OSWorkflow_DflyFFEnabled_WithSBOM_UsesSbomFlow(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := createMockEngine(ctrl)
	mockIctx := createMockInvocationCtxWithURL(t, ctrl, mockEngine)
	cfg := mockIctx.GetConfiguration()
	cfg.Set(constants.FeatureFlagDlfyCLIRollout, true)
	cfg.Set(constants.FeatureFlagDflySbomMonitor, true)
	cfg.Set(flags.FlagSBOM, "testdata/bom.json")
	cfg.Set(configuration.INPUT_DIRECTORY, t.TempDir())

	// The SBOM flow will fail at the file upload step since there's no real server,
	// but the routing to the SBOM path (not depgraph) is what we verify.
	_, err := osmonitor.OSWorkflow(mockIctx, []workflow.Data{})

	// An error from the SBOM path (file upload / test client), not from dep graph resolution.
	assert.Error(t, err)
	assert.NotContains(t, err.Error(), "failed to extract dependency graphs")
}

func Test_OSWorkflow_DflyFFDisabled_WithSBOM_SbomMonitorFFEnabled_UsesSbomFlow(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := createMockEngine(ctrl)
	mockIctx := createMockInvocationCtxWithURL(t, ctrl, mockEngine)
	cfg := mockIctx.GetConfiguration()
	cfg.Set(constants.FeatureFlagDflySbomMonitor, true)
	cfg.Set(flags.FlagSBOM, "testdata/bom.json")
	cfg.Set(configuration.INPUT_DIRECTORY, t.TempDir())

	_, err := osmonitor.OSWorkflow(mockIctx, []workflow.Data{})

	assert.Error(t, err)
	assert.NotContains(t, err.Error(), "failed to extract dependency graphs")
	assert.NotContains(t, err.Error(), "not available for your organization")
}

func Test_OSWorkflow_DflyFFEnabled_WithSBOM_SbomMonitorFFDisabled_ReturnsError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := createMockEngine(ctrl)
	mockIctx := createMockInvocationCtxWithURL(t, ctrl, mockEngine)
	cfg := mockIctx.GetConfiguration()
	cfg.Set(constants.FeatureFlagDlfyCLIRollout, true)
	cfg.Set(constants.FeatureFlagDflySbomMonitor, false)
	cfg.Set(flags.FlagSBOM, "testdata/bom.json")
	cfg.Set(configuration.INPUT_DIRECTORY, t.TempDir())

	_, err := osmonitor.OSWorkflow(mockIctx, []workflow.Data{})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not available for your organization")
}

func Test_OSWorkflow_DflyFFEnabled_WithoutSBOM_UsesDepgraphFlow(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := createMockEngine(ctrl)
	mockEngine.EXPECT().InvokeWithConfig(gomock.Any(), gomock.Any()).Return(nil, nil).AnyTimes()

	mockIctx := createMockInvocationCtxWithURL(t, ctrl, mockEngine)
	cfg := mockIctx.GetConfiguration()
	cfg.Set(constants.FeatureFlagDlfyCLIRollout, true)
	cfg.Set(configuration.INPUT_DIRECTORY, t.TempDir())
	cfg.Set(configuration.RAW_CMD_ARGS, "monitor "+t.TempDir())

	_, err := osmonitor.OSWorkflow(mockIctx, []workflow.Data{})

	// Error from the depgraph resolution path (no real project).
	assert.Error(t, err)
}
