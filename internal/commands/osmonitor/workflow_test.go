package osmonitor_test

import (
	"net/http"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/networking"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/bundlestore"
	"github.com/snyk/cli-extension-os-flows/internal/commands/osmonitor"
	"github.com/snyk/cli-extension-os-flows/internal/reachability"
)

func TestRegisterWorkflows(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mocks.NewMockEngine(ctrl)
	mockEngine.EXPECT().
		GetWorkflow(osmonitor.WorkflowID).
		Times(1)
	mockEngine.EXPECT().
		Register(osmonitor.WorkflowID, gomock.Any(), gomock.Any()).
		Times(1)
	mockInvocationCtx := createMockInvocationCtxWithURL(t, ctrl, mockEngine, "")
	mockConfig := mockInvocationCtx.GetConfiguration()

	mockEngine.EXPECT().GetConfiguration().Return(mockConfig).AnyTimes()

	err := osmonitor.RegisterWorkflows(mockEngine)
	require.NoError(t, err)
}

func Test_GetReachabilityID(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockEngine := mocks.NewMockEngine(ctrl)
	expectedReachabilityID := uuid.New()
	mockInvocationCtx := createMockInvocationCtxWithURL(t, ctrl, mockEngine, "")
	fbsc := bundlestore.NewFakeClient()
	frc := reachability.NewFakeClient(expectedReachabilityID)

	reachID, err := osmonitor.GetReachabilityID(t.Context(), mockInvocationCtx, fbsc, frc)
	require.NoError(t, err)

	assert.Equal(t, expectedReachabilityID, reachID)
	assert.Equal(t, 1, fbsc.GetUploadCount())
}

func Test_GetReachabilityID_FailedUploadingSourceCode(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockEngine := mocks.NewMockEngine(ctrl)
	expectedReachabilityID := uuid.New()
	mockInvocationCtx := createMockInvocationCtxWithURL(t, ctrl, mockEngine, "")
	fbsc := bundlestore.NewFakeClient()
	fbsc.WithError(assert.AnError)
	frc := reachability.NewFakeClient(expectedReachabilityID)

	_, err := osmonitor.GetReachabilityID(t.Context(), mockInvocationCtx, fbsc, frc)

	assert.ErrorContains(t, err, "failed to upload source code")
	assert.ErrorIs(t, err, assert.AnError)
	assert.Equal(t, 0, fbsc.GetUploadCount())
}

func Test_GetReachabilityID_FailedToStartReachabilityAnalysis(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockEngine := mocks.NewMockEngine(ctrl)
	expectedReachabilityID := uuid.New()
	mockInvocationCtx := createMockInvocationCtxWithURL(t, ctrl, mockEngine, "")
	fbsc := bundlestore.NewFakeClient()
	frc := reachability.NewFakeClient(expectedReachabilityID)
	frc.WithStartErr(assert.AnError)

	_, err := osmonitor.GetReachabilityID(t.Context(), mockInvocationCtx, fbsc, frc)

	assert.ErrorContains(t, err, "failed to start reachability analysis")
	assert.ErrorIs(t, err, assert.AnError)
	assert.Equal(t, 1, fbsc.GetUploadCount())
}

func Test_GetReachabilityID_FailedToAwaitReachabilityAnalysis(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockEngine := mocks.NewMockEngine(ctrl)
	expectedReachabilityID := uuid.New()
	mockInvocationCtx := createMockInvocationCtxWithURL(t, ctrl, mockEngine, "")
	fbsc := bundlestore.NewFakeClient()
	frc := reachability.NewFakeClient(expectedReachabilityID)
	frc.WithWaitErr(assert.AnError)

	_, err := osmonitor.GetReachabilityID(t.Context(), mockInvocationCtx, fbsc, frc)

	assert.ErrorContains(t, err, "failed waiting for reachability analysis results")
	assert.ErrorIs(t, err, assert.AnError)
	assert.Equal(t, 1, fbsc.GetUploadCount())
}

//nolint:unparam // The mock server url will be passed eventually.
func createMockInvocationCtxWithURL(t *testing.T, ctrl *gomock.Controller, engine workflow.Engine, mockServerURL string) workflow.InvocationContext {
	t.Helper()

	mockConfig := configuration.New()
	mockConfig.Set(configuration.AUTHENTICATION_TOKEN, "<SOME API TOKEN>")
	mockConfig.Set(configuration.ORGANIZATION, uuid.New().String())
	mockConfig.Set(configuration.ORGANIZATION_SLUG, "some-org")
	mockConfig.Set(configuration.API_URL, mockServerURL)

	mockLogger := zerolog.Nop()

	icontext := mocks.NewMockInvocationContext(ctrl)
	icontext.EXPECT().GetConfiguration().Return(mockConfig).AnyTimes()
	icontext.EXPECT().GetEnhancedLogger().Return(&mockLogger).AnyTimes()
	icontext.EXPECT().GetNetworkAccess().Return(networking.NewNetworkAccess(mockConfig)).AnyTimes()

	if engine != nil {
		icontext.EXPECT().GetEngine().Return(engine).AnyTimes()
	} else {
		icontext.EXPECT().GetEngine().Return(nil).AnyTimes()
	}

	// Mock network access
	mockNetwork := mocks.NewMockNetworkAccess(ctrl)
	mockNetwork.EXPECT().GetHttpClient().Return(&http.Client{}).AnyTimes()
	icontext.EXPECT().GetNetworkAccess().Return(mockNetwork).AnyTimes()

	return icontext
}
