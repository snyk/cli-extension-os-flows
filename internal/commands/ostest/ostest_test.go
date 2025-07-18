package ostest_test

import (
	"net/http"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/networking"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/cli-extension-os-flows/internal/commands/ostest"
	"github.com/snyk/cli-extension-os-flows/internal/flags"
)

const mockServerURL = "https://mock.server/api"

func TestOSWorkflow_LegacyFlow(t *testing.T) {
	// Setup - No special flags set
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mocks.NewMockEngine(ctrl)
	mockInvocationCtx := createMockInvocationCtxWithURL(t, ctrl, mockEngine, mockServerURL)

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

// TestOSWorkflow_UnifiedTestFlag tests the workflow when run with the unified test flag.
func TestOSWorkflow_UnifiedTestFlag(t *testing.T) {
	// Setup - Unified test flag set to true
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mocks.NewMockEngine(ctrl)
	mockInvocationCtx := createMockInvocationCtxWithURL(t, ctrl, mockEngine, mockServerURL)

	// Set the unified test flag and required risk score feature flags
	mockInvocationCtx.GetConfiguration().Set(flags.FlagUnifiedTestAPI, true)
	mockInvocationCtx.GetConfiguration().Set(ostest.FeatureFlagRiskScore, true)
	mockInvocationCtx.GetConfiguration().Set(ostest.FeatureFlagRiskScoreInCLI, true)

	// Mock the depgraph workflow
	mockEngine.EXPECT().
		InvokeWithConfig(gomock.Any(), gomock.Any()).
		Return(nil, assert.AnError).
		Times(1)

	// Execute
	_, err := ostest.OSWorkflow(mockInvocationCtx, []workflow.Data{})

	// Verify - Should return error from depgraph workflow
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create depgraph")
}

// TestOSWorkflow_RiskScoreThreshold tests the workflow when run with a risk score threshold.
func TestOSWorkflow_RiskScoreThreshold(t *testing.T) {
	// Setup - Risk score threshold set
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mocks.NewMockEngine(ctrl)
	mockInvocationCtx := createMockInvocationCtxWithURL(t, ctrl, mockEngine, mockServerURL)

	// Set a risk score threshold
	mockInvocationCtx.GetConfiguration().Set(flags.FlagRiskScoreThreshold, 700)
	// Enable Risk Score feature flags for this test case
	mockInvocationCtx.GetConfiguration().Set(ostest.FeatureFlagRiskScore, true)
	mockInvocationCtx.GetConfiguration().Set(ostest.FeatureFlagRiskScoreInCLI, true)

	// Mock the depgraph workflow
	mockEngine.EXPECT().
		InvokeWithConfig(gomock.Any(), gomock.Any()).
		Return(nil, assert.AnError).
		Times(1)

	// Execute
	_, err := ostest.OSWorkflow(mockInvocationCtx, []workflow.Data{})

	// Verify - Should return error from depgraph workflow
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create depgraph")
}

// TestOSWorkflow_SBOMReachabilityFlag_MissingFF tests requirement of the SBOM reachability feature flag.
func TestOSWorkflow_SBOMReachabilityFlag_MissingFF(t *testing.T) {
	// Setup - Unified test flag set to true
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mocks.NewMockEngine(ctrl)
	mockInvocationCtx := createMockInvocationCtxWithURL(t, ctrl, mockEngine, mockServerURL)

	// Set the sbom reachability flags
	mockInvocationCtx.GetConfiguration().Set(flags.FlagReachability, true)
	mockInvocationCtx.GetConfiguration().Set(flags.FlagSBOM, "bom.json")

	// Execute
	_, err := ostest.OSWorkflow(mockInvocationCtx, []workflow.Data{})

	// Verify - Should return feature not permitted error
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "The feature you are trying to use is not available for your organization")
}

// TODO: Test combinations with sbom and reachability flags.
func TestOSWorkflow_FlagCombinations(t *testing.T) {
	tests := []struct {
		name          string
		setup         func(config configuration.Configuration, mockEngine *mocks.MockEngine)
		expectedError string
	}{
		{
			name: "Unified test API flag set to true, expects depgraph error",
			setup: func(config configuration.Configuration, mockEngine *mocks.MockEngine) {
				config.Set(flags.FlagUnifiedTestAPI, true)
				config.Set(ostest.FeatureFlagRiskScore, true)
				config.Set(ostest.FeatureFlagRiskScoreInCLI, true)
				mockEngine.EXPECT().
					InvokeWithConfig(gomock.Any(), gomock.Any()).
					Return(nil, assert.AnError).
					Times(1) // Expect once if this path is taken
			},
			expectedError: "failed to create depgraph",
		},
		{
			name: "Risk Score Threshold set, primary Risk Score FF disabled",
			setup: func(config configuration.Configuration, _ *mocks.MockEngine) {
				config.Set(flags.FlagRiskScoreThreshold, 700)
				// Assuming ostest.FeatureFlagRiskScore is false by default
			},
			expectedError: "The feature you are trying to use is not available for your organization",
		},
		{
			name: "Risk Score Threshold set, primary FF enabled, CLI Risk Score FF disabled",
			setup: func(config configuration.Configuration, _ *mocks.MockEngine) {
				config.Set(flags.FlagRiskScoreThreshold, 700)
				config.Set(ostest.FeatureFlagRiskScore, true)
				// Assuming ostest.FeatureFlagRiskScoreInCLI is false by default
			},
			expectedError: "The feature you are trying to use is not available for your organization",
		},
		{
			name: "Risk Score Threshold set, all Risk Score FFs enabled, expects depgraph error",
			setup: func(config configuration.Configuration, mockEngine *mocks.MockEngine) {
				config.Set(flags.FlagRiskScoreThreshold, 700)
				config.Set(ostest.FeatureFlagRiskScore, true)
				config.Set(ostest.FeatureFlagRiskScoreInCLI, true)
				mockEngine.EXPECT().
					InvokeWithConfig(gomock.Any(), gomock.Any()).
					Return(nil, assert.AnError).
					Times(1) // Expect once if this path is taken after FFs pass
			},
			expectedError: "failed to create depgraph",
		},
		{
			name: "Both unified test and risk score set",
			setup: func(config configuration.Configuration, mockEngine *mocks.MockEngine) {
				config.Set(flags.FlagUnifiedTestAPI, true)
				config.Set(flags.FlagRiskScoreThreshold, 700)
				config.Set(ostest.FeatureFlagRiskScore, true)
				config.Set(ostest.FeatureFlagRiskScoreInCLI, true)
				mockEngine.EXPECT().
					InvokeWithConfig(gomock.Any(), gomock.Any()).
					Return(nil, assert.AnError).
					Times(1)
			},
			expectedError: "failed to create depgraph",
		},
		{
			name: "SBOM reachability without feature flag",
			setup: func(config configuration.Configuration, _ *mocks.MockEngine) {
				config.Set(flags.FlagReachability, true)
				config.Set(flags.FlagSBOM, "bom.json")
				// Don't set the feature flag
			},
			expectedError: "The feature you are trying to use is not available for your organization",
		},
		{
			name: "Severity threshold set with unified test flag, expects depgraph error",
			setup: func(config configuration.Configuration, mockEngine *mocks.MockEngine) {
				config.Set(flags.FlagUnifiedTestAPI, true)
				config.Set(flags.FlagSeverityThreshold, "high")
				mockEngine.EXPECT().
					InvokeWithConfig(gomock.Any(), gomock.Any()).
					Return(nil, assert.AnError).
					Times(1)
			},
			expectedError: "failed to create depgraph",
		},
		{
			name: "Severity threshold set with risk score threshold, expects depgraph error",
			setup: func(config configuration.Configuration, mockEngine *mocks.MockEngine) {
				config.Set(flags.FlagRiskScoreThreshold, 500)
				config.Set(flags.FlagSeverityThreshold, "medium")
				config.Set(ostest.FeatureFlagRiskScore, true)
				config.Set(ostest.FeatureFlagRiskScoreInCLI, true)
				mockEngine.EXPECT().
					InvokeWithConfig(gomock.Any(), gomock.Any()).
					Return(nil, assert.AnError).
					Times(1)
			},
			expectedError: "failed to create depgraph",
		},
		{
			name: "Severity threshold alone, uses legacy flow",
			setup: func(config configuration.Configuration, mockEngine *mocks.MockEngine) {
				config.Set(flags.FlagSeverityThreshold, "low")
				mockEngine.EXPECT().
					InvokeWithConfig(gomock.Any(), gomock.Any()).
					Return([]workflow.Data{}, nil).
					Times(1)
			},
			expectedError: "", // No error, should succeed via legacy path
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockEngine := mocks.NewMockEngine(ctrl)
			mockInvocationCtx := createMockInvocationCtxWithURL(t, ctrl, mockEngine, mockServerURL)

			// Setup test case
			test.setup(mockInvocationCtx.GetConfiguration(), mockEngine)

			// Execute
			_, err := ostest.OSWorkflow(mockInvocationCtx, []workflow.Data{})

			// Verify
			if test.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), test.expectedError, "Expected error to contain: %s", test.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Helpers

// createMockInvocationCtx creates a mock invocation context with default values for our flags.
func createMockInvocationCtxWithURL(t *testing.T, ctrl *gomock.Controller, engine workflow.Engine, sbomServiceURL string) workflow.InvocationContext {
	t.Helper()

	mockConfig := configuration.New()
	mockConfig.Set(configuration.AUTHENTICATION_TOKEN, "<SOME API TOKEN>")
	mockConfig.Set(configuration.ORGANIZATION, "test-org")
	mockConfig.Set(configuration.API_URL, sbomServiceURL)

	// Initialize with default values for our flags
	mockConfig.Set(flags.FlagUnifiedTestAPI, false)
	mockConfig.Set(flags.FlagRiskScoreThreshold, -1)
	mockConfig.Set(flags.FlagFile, "test-file.txt") // Add default test file

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
