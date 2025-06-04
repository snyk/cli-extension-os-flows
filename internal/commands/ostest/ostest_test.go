package ostest_test

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/cli-extension-os-flows/internal/commands/ostest"
	"github.com/snyk/cli-extension-os-flows/internal/flags"
)

func TestOSWorkflow_LegacyFlow(t *testing.T) {
	// Setup - No special flags set
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mocks.NewMockEngine(ctrl)
	mockInvocationCtx := createMockInvocationCtx(ctrl, mockEngine)

	// Mock the legacy flow to return successfully
	mockEngine.EXPECT().
		InvokeWithConfig(gomock.Any(), gomock.Any()).
		Return([]workflow.Data{}, nil).
		Times(1)

	// Execute
	_, err := ostest.OSWorkflow(mockInvocationCtx, []workflow.Data{})

	// Verify
	assert.NoError(t, err)
}

func TestOSWorkflow_UnifiedTestFlag(t *testing.T) {
	// Setup - Unified test flag set to true
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mocks.NewMockEngine(ctrl)
	mockInvocationCtx := createMockInvocationCtx(ctrl, mockEngine)

	// Set the unified test flag
	mockInvocationCtx.GetConfiguration().Set(flags.FlagUnifiedTestAPI, true)

	// Execute
	_, err := ostest.OSWorkflow(mockInvocationCtx, []workflow.Data{})

	// Verify - Should return not implemented error
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "feature is not yet available")
}

func TestOSWorkflow_RiskScoreThreshold(t *testing.T) {
	// Setup - Risk score threshold set
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mocks.NewMockEngine(ctrl)
	mockInvocationCtx := createMockInvocationCtx(ctrl, mockEngine)

	// Set a risk score threshold
	mockInvocationCtx.GetConfiguration().Set(flags.FlagRiskScoreThreshold, 700)

	// Execute
	_, err := ostest.OSWorkflow(mockInvocationCtx, []workflow.Data{})

	// Verify - Should return not implemented error
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "feature is not yet available")
}

func TestOSWorkflow_SBOMReachabilityFlag_MissingFF(t *testing.T) {
	// Setup - Unified test flag set to true
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mocks.NewMockEngine(ctrl)
	mockInvocationCtx := createMockInvocationCtx(ctrl, mockEngine)

	// Set the sbom reachability flags
	mockInvocationCtx.GetConfiguration().Set(flags.FlagReachability, true)
	mockInvocationCtx.GetConfiguration().Set(flags.FlagSBOM, "bom.json")

	// Execute
	_, err := ostest.OSWorkflow(mockInvocationCtx, []workflow.Data{})

	// Verify - Should return not implemented error
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "The feature you are trying to use is not available for your organization.")
}

func TestOSWorkflow_SBOMReachabilityFlag(t *testing.T) {
	// Setup - Unified test flag set to true
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mocks.NewMockEngine(ctrl)
	mockInvocationCtx := createMockInvocationCtx(ctrl, mockEngine)

	// Set the sbom reachability flags
	mockInvocationCtx.GetConfiguration().Set(flags.FlagReachability, true)
	mockInvocationCtx.GetConfiguration().Set(flags.FlagSBOM, "bom.json")
	mockInvocationCtx.GetConfiguration().Set(ostest.FeatureFlagSBOMTestReachability, true)

	// Execute
	_, err := ostest.OSWorkflow(mockInvocationCtx, []workflow.Data{})

	// Verify - Should return not implemented error
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "feature is not yet available")
}

// TODO: Test combinations with sbom and reachability flags.
func TestOSWorkflow_FlagCombinations(t *testing.T) {
	tests := []struct {
		name               string
		unifiedTestAPI     bool
		riskScoreThreshold int
		expectedError      string
	}{
		{
			name:               "Unified test API flag set to true",
			unifiedTestAPI:     true,
			riskScoreThreshold: -1, // -1 is default == not set
			expectedError:      "feature is not yet available",
		},
		{
			name:               "Risk score threshold set",
			unifiedTestAPI:     false,
			riskScoreThreshold: 700,
			expectedError:      "feature is not yet available",
		},
		{
			name:               "Both flags set",
			unifiedTestAPI:     true,
			riskScoreThreshold: 700,
			expectedError:      "feature is not yet available",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockEngine := mocks.NewMockEngine(ctrl)
			mockInvocationCtx := createMockInvocationCtx(ctrl, mockEngine)

			// Set the flags
			mockInvocationCtx.GetConfiguration().Set(flags.FlagUnifiedTestAPI, test.unifiedTestAPI)
			mockInvocationCtx.GetConfiguration().Set(flags.FlagRiskScoreThreshold, test.riskScoreThreshold)

			// Execute
			_, err := ostest.OSWorkflow(mockInvocationCtx, []workflow.Data{})

			// Verify - Should return not implemented error
			assert.Error(t, err)
			assert.Contains(t, err.Error(), test.expectedError)
		})
	}
}

// Helpers

// createMockInvocationCtx creates a mock invocation context with default values for our flags.
func createMockInvocationCtx(ctrl *gomock.Controller, engine workflow.Engine) workflow.InvocationContext {
	mockConfig := configuration.New()
	mockConfig.Set(configuration.AUTHENTICATION_TOKEN, "<SOME API TOKEN>")
	mockConfig.Set(configuration.API_URL, "https://mock.server/api")

	// Initialize with default values for our flags
	mockConfig.Set(flags.FlagUnifiedTestAPI, false)
	mockConfig.Set(flags.FlagRiskScoreThreshold, -1)

	mockLogger := zerolog.Nop()

	icontext := mocks.NewMockInvocationContext(ctrl)
	icontext.EXPECT().GetConfiguration().Return(mockConfig).AnyTimes()
	icontext.EXPECT().GetEnhancedLogger().Return(&mockLogger).AnyTimes()

	if engine != nil {
		icontext.EXPECT().GetEngine().Return(engine).AnyTimes()
	}

	return icontext
}
