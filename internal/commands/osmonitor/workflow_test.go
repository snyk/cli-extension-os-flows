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
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/commands/osmonitor"
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
