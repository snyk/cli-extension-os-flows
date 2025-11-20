package ostest_test

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/analytics"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/content_type"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/networking"
	"github.com/snyk/go-application-framework/pkg/ui"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	"github.com/snyk/cli-extension-os-flows/internal/commands/ostest"
	common "github.com/snyk/cli-extension-os-flows/internal/common"
	"github.com/snyk/cli-extension-os-flows/internal/constants"
	"github.com/snyk/cli-extension-os-flows/internal/errors"
	"github.com/snyk/cli-extension-os-flows/internal/flags"
	"github.com/snyk/cli-extension-os-flows/internal/legacy/definitions"
	"github.com/snyk/cli-extension-os-flows/internal/outputworkflow"
	"github.com/snyk/cli-extension-os-flows/internal/util"
)

var (
	legacyWorkflowID = workflow.NewWorkflowIdentifier("legacycli")
	logger           = zerolog.Nop()
	errFactory       = errors.NewErrorFactory(&logger)
	nopProgressBar   = NopProgressBar{}
)

type NopProgressBar struct{}

func (npb *NopProgressBar) SetTitle(_ string)                                    {}
func (npb *NopProgressBar) UpdateProgress(_ float64) error                       { return nil }
func (npb *NopProgressBar) Clear() error                                         { return nil }
func (npb *NopProgressBar) SetCompletionMessage(_ string)                        {}
func (npb *NopProgressBar) SetCompletionMessageWithStyle(_, _ string)            {}
func (npb *NopProgressBar) SetCompletionMessageWithTitle(_, _ string)            {}
func (npb *NopProgressBar) SetCompletionMessageWithTitleAndStyle(_, _, _ string) {}

func TestOSWorkflow_CreateLocalPolicy(t *testing.T) {
	tests := []struct {
		name                     string
		failOnValue              string
		setFailOnFlag            bool
		expectedFailOnUpgradable *bool
	}{
		{
			name:                     "no fail-on flag set",
			setFailOnFlag:            false,
			expectedFailOnUpgradable: nil,
		},
		{
			name:                     "fail-on upgradable",
			failOnValue:              "upgradable",
			setFailOnFlag:            true,
			expectedFailOnUpgradable: util.Ptr(true),
		},
		{
			name:                     "fail-on all",
			failOnValue:              "all",
			setFailOnFlag:            true,
			expectedFailOnUpgradable: util.Ptr(true),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockEngine := mocks.NewMockEngine(ctrl)
			mockInvocationCtx := createMockInvocationCtxWithURL(t, ctrl, mockEngine, "")
			mockConfig := mockInvocationCtx.GetConfiguration()

			mockConfig.Set(flags.FlagRiskScoreThreshold, 100)
			mockConfig.Set(flags.FlagSeverityThreshold, "high")

			ctx := t.Context()
			ctx = cmdctx.WithIctx(ctx, mockInvocationCtx)
			ctx = cmdctx.WithConfig(ctx, mockConfig)
			ctx = cmdctx.WithLogger(ctx, &logger)
			ctx = cmdctx.WithErrorFactory(ctx, errFactory)
			ctx = cmdctx.WithProgressBar(ctx, &nopProgressBar)

			if tt.setFailOnFlag {
				mockConfig.Set(flags.FlagFailOn, tt.failOnValue)
			}

			localPolicy, err := ostest.CreateLocalPolicy(ctx, ".")
			require.NoError(t, err)

			require.NotNil(t, localPolicy)

			require.NotNil(t, localPolicy.RiskScoreThreshold)
			assert.Equal(t, uint16(100), *localPolicy.RiskScoreThreshold)

			require.NotNil(t, localPolicy.SeverityThreshold)
			assert.Equal(t, "high", string(*localPolicy.SeverityThreshold))

			if tt.expectedFailOnUpgradable == nil {
				assert.Nil(t, localPolicy.FailOnUpgradable)
			} else {
				require.NotNil(t, localPolicy.FailOnUpgradable)
				assert.Equal(t, *tt.expectedFailOnUpgradable, *localPolicy.FailOnUpgradable)
			}
		})
	}
}

func TestOSWorkflow_CreateLocalPolicy_UnsupportedFailOnValue(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mocks.NewMockEngine(ctrl)
	mockInvocationCtx := createMockInvocationCtxWithURL(t, ctrl, mockEngine, "")
	mockConfig := mockInvocationCtx.GetConfiguration()

	mockConfig.Set(flags.FlagFailOn, "unsupported")

	ctx := t.Context()
	ctx = cmdctx.WithIctx(ctx, mockInvocationCtx)
	ctx = cmdctx.WithConfig(ctx, mockConfig)
	ctx = cmdctx.WithLogger(ctx, &logger)
	ctx = cmdctx.WithErrorFactory(ctx, errFactory)
	ctx = cmdctx.WithProgressBar(ctx, &nopProgressBar)

	localPolicy, err := ostest.CreateLocalPolicy(ctx, ".")
	require.Error(t, err)
	assert.Nil(t, localPolicy)
	assert.Contains(t, err.Error(), "Unsupported value 'unsupported' for --fail-on flag")
	assert.Contains(t, err.Error(), "Supported values are: 'all', 'upgradable'")
}

func TestOSWorkflow_CreateLocalPolicy_NoValues(t *testing.T) {
	// Setup - No special flags set
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mocks.NewMockEngine(ctrl)
	mockInvocationCtx := createMockInvocationCtxWithURL(t, ctrl, mockEngine, "")
	mockConfig := mockInvocationCtx.GetConfiguration()
	ctx := t.Context()
	ctx = cmdctx.WithIctx(ctx, mockInvocationCtx)
	ctx = cmdctx.WithConfig(ctx, mockConfig)
	ctx = cmdctx.WithLogger(ctx, &logger)
	ctx = cmdctx.WithErrorFactory(ctx, errFactory)
	ctx = cmdctx.WithProgressBar(ctx, &nopProgressBar)

	localPolicy, err := ostest.CreateLocalPolicy(ctx, ".")
	require.NoError(t, err)

	assert.Nil(t, localPolicy)
}

func TestOSWorkflow_CreateLocalPolicy_RiskScoreOverflow(t *testing.T) {
	// Setup - No special flags set
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mocks.NewMockEngine(ctrl)
	mockInvocationCtx := createMockInvocationCtxWithURL(t, ctrl, mockEngine, "")
	mockConfig := mockInvocationCtx.GetConfiguration()
	mockConfig.Set(flags.FlagRiskScoreThreshold, math.MaxUint16+10)
	ctx := t.Context()
	ctx = cmdctx.WithIctx(ctx, mockInvocationCtx)
	ctx = cmdctx.WithConfig(ctx, mockConfig)
	ctx = cmdctx.WithLogger(ctx, &logger)
	ctx = cmdctx.WithErrorFactory(ctx, errFactory)
	ctx = cmdctx.WithProgressBar(ctx, &nopProgressBar)

	localPolicy, err := ostest.CreateLocalPolicy(ctx, ".")
	require.NoError(t, err)
	require.NotNil(t, localPolicy)

	assert.NotNil(t, localPolicy.RiskScoreThreshold)
	assert.Equal(t, uint16(math.MaxUint16), *localPolicy.RiskScoreThreshold)
}

func TestOSWorkflow_CreateLocalPolicy_SeverityThresholdDefaultsToNone(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mocks.NewMockEngine(ctrl)
	mockInvocationCtx := createMockInvocationCtxWithURL(t, ctrl, mockEngine, "")
	mockConfig := mockInvocationCtx.GetConfiguration()

	mockConfig.Set(flags.FlagRiskScoreThreshold, 100)
	mockConfig.Set(flags.FlagSeverityThreshold, "")
	ctx := t.Context()
	ctx = cmdctx.WithIctx(ctx, mockInvocationCtx)
	ctx = cmdctx.WithConfig(ctx, mockConfig)
	ctx = cmdctx.WithLogger(ctx, &logger)
	ctx = cmdctx.WithErrorFactory(ctx, errFactory)
	ctx = cmdctx.WithProgressBar(ctx, &nopProgressBar)

	localPolicy, err := ostest.CreateLocalPolicy(ctx, ".")
	require.NoError(t, err)
	require.NotNil(t, localPolicy)

	require.NotNil(t, localPolicy.RiskScoreThreshold)
	assert.Equal(t, uint16(100), *localPolicy.RiskScoreThreshold)

	require.NotNil(t, localPolicy.SeverityThreshold)
	assert.Equal(t, testapi.SeverityNone, *localPolicy.SeverityThreshold)
}

func TestOSWorkflow_CreateLocalPolicy_ReachabilityFilterDefaultBehavior(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mocks.NewMockEngine(ctrl)
	mockInvocationCtx := createMockInvocationCtxWithURL(t, ctrl, mockEngine, "")
	mockConfig := mockInvocationCtx.GetConfiguration()

	mockConfig.Set(flags.FlagRiskScoreThreshold, 100)
	mockConfig.Set(flags.FlagReachabilityFilter, "")
	ctx := t.Context()
	ctx = cmdctx.WithIctx(ctx, mockInvocationCtx)
	ctx = cmdctx.WithConfig(ctx, mockConfig)
	ctx = cmdctx.WithLogger(ctx, &logger)
	ctx = cmdctx.WithErrorFactory(ctx, errFactory)
	ctx = cmdctx.WithProgressBar(ctx, &nopProgressBar)

	localPolicy, err := ostest.CreateLocalPolicy(ctx, ".")
	require.NoError(t, err)
	require.NotNil(t, localPolicy)

	require.NotNil(t, localPolicy.RiskScoreThreshold)
	assert.Equal(t, uint16(100), *localPolicy.RiskScoreThreshold)

	require.NotNil(t, localPolicy.SeverityThreshold)
	assert.Equal(t, testapi.SeverityNone, *localPolicy.SeverityThreshold)

	assert.Nil(t, localPolicy.ReachabilityFilter)
}

func TestOSWorkflow_CreateLocalPolicy_ReachabilityFilter(t *testing.T) {
	tests := []struct {
		name          string
		filterValue   string
		expectFilter  bool
		expectedValue testapi.ReachabilityFilter
	}{
		{
			name:          "reachable",
			filterValue:   "reachable",
			expectFilter:  true,
			expectedValue: testapi.ReachabilityFilterReachable,
		},
		{
			name:          "no-path-found",
			filterValue:   "no-path-found",
			expectFilter:  true,
			expectedValue: testapi.ReachabilityFilterNoPathFound,
		},
		{
			name:          "not-applicable",
			filterValue:   "not-applicable",
			expectFilter:  true,
			expectedValue: testapi.ReachabilityFilterNoInfo,
		},
		{
			name:          "no path found",
			filterValue:   "no path found",
			expectFilter:  true,
			expectedValue: testapi.ReachabilityFilterNoPathFound,
		},
		{
			name:          "not applicable",
			filterValue:   "not applicable",
			expectFilter:  true,
			expectedValue: testapi.ReachabilityFilterNoInfo,
		},
		{
			name:         "invalid value",
			filterValue:  "non-existent-filter",
			expectFilter: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := configuration.New()
			config.Set(flags.FlagReachabilityFilter, tt.filterValue)

			ctx := t.Context()
			ctx = cmdctx.WithConfig(ctx, config)
			ctx = cmdctx.WithLogger(ctx, &logger)
			ctx = cmdctx.WithErrorFactory(ctx, errFactory)
			ctx = cmdctx.WithProgressBar(ctx, &nopProgressBar)

			localPolicy, err := ostest.CreateLocalPolicy(ctx, ".")
			require.NoError(t, err)
			assert.Equal(t, tt.expectFilter, localPolicy.ReachabilityFilter != nil)

			// only match filter when available
			if tt.expectFilter {
				assert.Equal(t, tt.expectedValue, *localPolicy.ReachabilityFilter)
			}
		})
	}
}

func TestOSWorkflow_CreateLocalPolicy_NoLegacyPolicy(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mocks.NewMockEngine(ctrl)
	mockInvocationCtx := createMockInvocationCtxWithURL(t, ctrl, mockEngine, "")
	mockConfig := mockInvocationCtx.GetConfiguration()
	mockConfig.Set(flags.FlagRiskScoreThreshold, 100)
	ctx := t.Context()
	ctx = cmdctx.WithIctx(ctx, mockInvocationCtx)
	ctx = cmdctx.WithConfig(ctx, mockConfig)
	ctx = cmdctx.WithLogger(ctx, &logger)
	ctx = cmdctx.WithErrorFactory(ctx, errFactory)
	ctx = cmdctx.WithProgressBar(ctx, &nopProgressBar)

	localPolicy, _ := ostest.CreateLocalPolicy(ctx, ".")
	require.NotNil(t, localPolicy)
	assert.Nil(t, localPolicy.Ignores)
}

func TestOSWorkflow_CreateLocalPolicy_WithLegacyPolicy(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mocks.NewMockEngine(ctrl)
	mockInvocationCtx := createMockInvocationCtxWithURL(t, ctrl, mockEngine, "")
	mockConfig := mockInvocationCtx.GetConfiguration()
	mockConfig.Set(flags.FlagRiskScoreThreshold, 100)

	dir := createTempLegacyPolicy(t, `
version: v1.0.0
ignore:
  'npm:hawk:20160119':
    - sqlite > sqlite3 > node-pre-gyp > request > hawk:
        reason: hawk got bumped
        expires: '2116-03-01T14:30:04.136Z'
`)

	mockConfig.Set(configuration.INPUT_DIRECTORY, dir)
	ctx := t.Context()
	ctx = cmdctx.WithIctx(ctx, mockInvocationCtx)
	ctx = cmdctx.WithConfig(ctx, mockConfig)
	ctx = cmdctx.WithLogger(ctx, &logger)
	ctx = cmdctx.WithErrorFactory(ctx, errFactory)
	ctx = cmdctx.WithProgressBar(ctx, &nopProgressBar)

	localPolicy, _ := ostest.CreateLocalPolicy(ctx, dir)
	require.NotNil(t, localPolicy)
	require.NotNil(t, localPolicy.Ignores)
	assert.Len(t, *localPolicy.Ignores, 1)
}

func TestOSWorkflow_CreateLocalPolicy_PointingAtLegacyPolicy(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mocks.NewMockEngine(ctrl)
	mockInvocationCtx := createMockInvocationCtxWithURL(t, ctrl, mockEngine, "")
	mockConfig := mockInvocationCtx.GetConfiguration()
	mockConfig.Set(flags.FlagRiskScoreThreshold, 100)

	dir := createTempLegacyPolicy(t, `
version: v1.0.0
ignore:
  'npm:hawk:20160119':
    - sqlite > sqlite3 > node-pre-gyp > request > hawk:
        reason: hawk got bumped
        expires: '2116-03-01T14:30:04.136Z'
`)

	mockConfig.Set(flags.FlagPolicyPath, dir)
	ctx := t.Context()
	ctx = cmdctx.WithIctx(ctx, mockInvocationCtx)
	ctx = cmdctx.WithConfig(ctx, mockConfig)
	ctx = cmdctx.WithLogger(ctx, &logger)
	ctx = cmdctx.WithErrorFactory(ctx, errFactory)
	ctx = cmdctx.WithProgressBar(ctx, &nopProgressBar)

	localPolicy, _ := ostest.CreateLocalPolicy(ctx, ".")
	require.NotNil(t, localPolicy)
	require.NotNil(t, localPolicy.Ignores)
	assert.Len(t, *localPolicy.Ignores, 1)
}

func TestOSWorkflow_LegacyFlow(t *testing.T) {
	// Setup - No special flags set
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mocks.NewMockEngine(ctrl)
	mockInvocationCtx := createMockInvocationCtxWithURL(t, ctrl, mockEngine, "")

	// Mock the legacy flow to return successfully
	mockEngine.EXPECT().
		InvokeWithConfig(legacyWorkflowID, gomock.Any()).
		Return([]workflow.Data{}, nil).
		Times(1)

	// Execute
	_, err := ostest.OSWorkflow(mockInvocationCtx, []workflow.Data{})

	// Verify
	assert.NoError(t, err)
}

func TestOSWorkflow_OrgIDHandling(t *testing.T) {
	tests := []struct {
		name          string
		setupConfig   func(config configuration.Configuration)
		setupEngine   func(mockEngine *mocks.MockEngine)
		expectError   bool
		errorContains string
	}{
		{
			name: "Legacy flow without org ID should route to legacy",
			setupConfig: func(config configuration.Configuration) {
				config.Set(configuration.ORGANIZATION, "")
			},
			setupEngine: func(mockEngine *mocks.MockEngine) {
				mockEngine.EXPECT().
					InvokeWithConfig(legacyWorkflowID, gomock.Any()).
					Return([]workflow.Data{}, nil).
					Times(1)
			},
			expectError: false,
		},
		{
			name: "New flow without org ID should fail with org error",
			setupConfig: func(config configuration.Configuration) {
				config.Set(configuration.ORGANIZATION, "")
				config.Set(constants.FeatureFlagRiskScore, true)
				config.Set(constants.FeatureFlagRiskScoreInCLI, true)
			},
			setupEngine: func(_ *mocks.MockEngine) {
			},
			expectError:   true,
			errorContains: "Snyk failed to infer an organization ID",
		},
		{
			name: "New flow with invalid org ID should fail with invalid org error",
			setupConfig: func(config configuration.Configuration) {
				config.Set(configuration.ORGANIZATION, "not-a-valid-uuid")
				config.Set(constants.FeatureFlagRiskScore, true)
				config.Set(constants.FeatureFlagRiskScoreInCLI, true)
			},
			setupEngine: func(_ *mocks.MockEngine) {
			},
			expectError:   true,
			errorContains: "not valid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockEngine := mocks.NewMockEngine(ctrl)
			mockInvocationCtx := createMockInvocationCtxWithURL(t, ctrl, mockEngine, "")
			config := mockInvocationCtx.GetConfiguration()

			tt.setupConfig(config)
			tt.setupEngine(mockEngine)

			_, err := ostest.OSWorkflow(mockInvocationCtx, []workflow.Data{})

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestOSWorkflow_FlagCombinations tests various flag combinations to ensure correct routing
// between the legacy, unified, and reachability test flows.
func TestOSWorkflow_FlagCombinations(t *testing.T) {
	tests := []struct {
		name          string
		setup         func(config configuration.Configuration, mockEngine *mocks.MockEngine)
		expectedError string
	}{
		{
			name: "Risk score FFs enabled, expects unified flow (depgraph error)",
			setup: func(config configuration.Configuration, mockEngine *mocks.MockEngine) {
				config.Set(constants.FeatureFlagRiskScore, true)
				config.Set(constants.FeatureFlagRiskScoreInCLI, true)
				mockEngine.EXPECT().
					InvokeWithConfig(common.DepGraphWorkflowID, gomock.Any()).
					Return(nil, assert.AnError).
					Times(1) // Expect once if this path is taken
			},
			expectedError: "failed to get dependency graph",
		},
		{
			name: "Risk Score Threshold set, Risk Score FFs disabled",
			setup: func(config configuration.Configuration, _ *mocks.MockEngine) {
				config.Set(flags.FlagRiskScoreThreshold, 700)
				// Assuming ostest.FeatureFlagRiskScore is false by default
			},
			expectedError: "The feature you are trying to use is not available for your organization",
		},
		{
			name: "Risk Score Threshold set, CLI Risk Score FF disabled",
			setup: func(config configuration.Configuration, _ *mocks.MockEngine) {
				config.Set(flags.FlagRiskScoreThreshold, 700)
				config.Set(constants.FeatureFlagRiskScore, true)
				// Assuming ostest.FeatureFlagRiskScoreInCLI is false by default
			},
			expectedError: "The feature you are trying to use is not available for your organization",
		},
		{
			name: "Risk Score Threshold set, both Risk Score FFs enabled, expects depgraph error",
			setup: func(config configuration.Configuration, mockEngine *mocks.MockEngine) {
				config.Set(flags.FlagRiskScoreThreshold, 700)
				config.Set(constants.FeatureFlagRiskScore, true)
				config.Set(constants.FeatureFlagRiskScoreInCLI, true)
				mockEngine.EXPECT().
					InvokeWithConfig(common.DepGraphWorkflowID, gomock.Any()).
					Return(nil, assert.AnError).
					Times(1) // Expect once if this path is taken after FFs pass
			},
			expectedError: "failed to get dependency graph",
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
			name: "Severity threshold set with FFs enabled, expects depgraph error",
			setup: func(config configuration.Configuration, mockEngine *mocks.MockEngine) {
				config.Set(constants.FeatureFlagRiskScore, true)
				config.Set(constants.FeatureFlagRiskScoreInCLI, true)
				config.Set(flags.FlagSeverityThreshold, "high")
				mockEngine.EXPECT().
					InvokeWithConfig(common.DepGraphWorkflowID, gomock.Any()).
					Return(nil, assert.AnError).
					Times(1)
			},
			expectedError: "failed to get dependency graph",
		},
		{
			name: "Severity threshold set with risk score threshold, expects depgraph error",
			setup: func(config configuration.Configuration, mockEngine *mocks.MockEngine) {
				config.Set(flags.FlagRiskScoreThreshold, 500)
				config.Set(flags.FlagSeverityThreshold, "medium")
				config.Set(constants.FeatureFlagRiskScore, true)
				config.Set(constants.FeatureFlagRiskScoreInCLI, true)
				mockEngine.EXPECT().
					InvokeWithConfig(common.DepGraphWorkflowID, gomock.Any()).
					Return(nil, assert.AnError).
					Times(1)
			},
			expectedError: "failed to get dependency graph",
		},
		{
			name: "Severity threshold without FFs enabled, uses legacy flow",
			setup: func(config configuration.Configuration, mockEngine *mocks.MockEngine) {
				config.Set(flags.FlagSeverityThreshold, "low")
				mockEngine.EXPECT().
					InvokeWithConfig(legacyWorkflowID, gomock.Any()).
					Return([]workflow.Data{}, nil).
					Times(1)
			},
			expectedError: "", // No error, should succeed via legacy path
		},
		{
			name: "All projects flag without FFs enabled, uses legacy flow",
			setup: func(config configuration.Configuration, mockEngine *mocks.MockEngine) {
				config.Set(flags.FlagAllProjects, true)
				mockEngine.EXPECT().
					InvokeWithConfig(legacyWorkflowID, gomock.Any()).
					Return([]workflow.Data{}, nil).
					Times(1)
			},
			expectedError: "", // No error, should succeed via legacy path
		},
		{
			name: "Only one risk score FF enabled, uses legacy flow",
			setup: func(config configuration.Configuration, mockEngine *mocks.MockEngine) {
				config.Set(constants.FeatureFlagRiskScore, true)
				// ffRiskScoreInCLI is false by default
				mockEngine.EXPECT().
					InvokeWithConfig(gomock.Any(), gomock.Any()).
					Return([]workflow.Data{}, nil).
					Times(1)
			},
			expectedError: "", // No error, should succeed via legacy path
		},
		{
			name: "Only CLI risk score FF enabled, uses legacy flow",
			setup: func(config configuration.Configuration, mockEngine *mocks.MockEngine) {
				config.Set(constants.FeatureFlagRiskScoreInCLI, true)
				// ffRiskScore is false by default
				mockEngine.EXPECT().
					InvokeWithConfig(gomock.Any(), gomock.Any()).
					Return([]workflow.Data{}, nil).
					Times(1)
			},
			expectedError: "", // No error, should succeed via legacy path
		},
		{
			name: "CLI Reachability FF enabled, expects unified flow (depgraph error)",
			setup: func(config configuration.Configuration, mockEngine *mocks.MockEngine) {
				config.Set(constants.FeatureFlagReachabilityForCLI, true)
				config.Set(flags.FlagReachability, true)
				mockEngine.EXPECT().
					InvokeWithConfig(common.DepGraphWorkflowID, gomock.Any()).
					Return(nil, assert.AnError).
					Times(1)
			},
			expectedError: "failed to get dependency graph",
		},
		{
			name: "Reachability set, CLI Reachability FF disabled",
			setup: func(config configuration.Configuration, _ *mocks.MockEngine) {
				config.Set(flags.FlagReachability, true)
			},
			expectedError: "Reachability settings not enabled",
		},
		{
			name: "UV test flow enabled with uv.lock file should use depgraph workflow with SBOM resolution",
			setup: func(config configuration.Configuration, mockEngine *mocks.MockEngine) {
				// Create temp directory with uv.lock file
				tempDir := util.CreateTempDirWithUvLock(t)
				config.Set(configuration.INPUT_DIRECTORY, []string{tempDir})
				config.Set(configuration.FLAG_EXPERIMENTAL, true)
				config.Set(constants.EnableExperimentalUvSupportEnvVar, true)
				mockEngine.EXPECT().
					InvokeWithConfig(common.DepGraphWorkflowID, gomock.Any()).
					DoAndReturn(func(_ workflow.Identifier, cfg configuration.Configuration) ([]workflow.Data, error) {
						// Verify that use-sbom-resolution flag is set
						if !cfg.GetBool("use-sbom-resolution") {
							return nil, fmt.Errorf("Expected use-sbom-resolution flag to be set")
						}
						return nil, assert.AnError
					}).
					Times(1)
			},
			expectedError: "failed to get dependency graph",
		},
		{
			name: "UV test flow enabled without uv.lock file should fall back to legacy flow",
			setup: func(config configuration.Configuration, mockEngine *mocks.MockEngine) {
				// Create temp directory without uv.lock file
				tempDir := t.TempDir()
				config.Set(configuration.INPUT_DIRECTORY, []string{tempDir})
				config.Set(configuration.FLAG_EXPERIMENTAL, true)
				config.Set(constants.EnableExperimentalUvSupportEnvVar, true)

				// Should route directly to legacy flow (not depgraph workflow)
				mockEngine.EXPECT().
					InvokeWithConfig(common.DepGraphWorkflowID, gomock.Any()).
					Times(0)
				mockEngine.EXPECT().
					InvokeWithConfig(legacyWorkflowID, gomock.Any()).
					Return([]workflow.Data{}, nil).
					Times(1)
			},
			expectedError: "", // No error, should succeed via legacy flow
		},
		{
			name: "UV test flow disabled should use legacy flow",
			setup: func(config configuration.Configuration, mockEngine *mocks.MockEngine) {
				config.Set(constants.EnableExperimentalUvSupportEnvVar, false)
				// When UV is disabled, should route directly to legacy flow
				mockEngine.EXPECT().
					InvokeWithConfig(legacyWorkflowID, gomock.Any()).
					Return([]workflow.Data{}, nil).
					Times(1)
			},
			expectedError: "", // No error, should succeed via legacy flow
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockAPI := newMockAPIState(t)
			defer mockAPI.Close()

			mockEngine := mocks.NewMockEngine(ctrl)
			mockInvocationCtx := createMockInvocationCtxWithURL(t, ctrl, mockEngine, mockAPI.URL())

			// Setup test case
			test.setup(mockInvocationCtx.GetConfiguration(), mockEngine)

			// Execute
			_, err := ostest.OSWorkflow(mockInvocationCtx, []workflow.Data{})

			// Verify
			if test.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.expectedError, "Expected error to contain: %s", test.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Helpers

// createMockInvocationCtx creates a mock invocation context with default values for our flags.
func createMockInvocationCtxWithURL(t *testing.T, ctrl *gomock.Controller, engine workflow.Engine, mockServerURL string) workflow.InvocationContext {
	t.Helper()

	mockConfig := configuration.New()
	mockConfig.Set(configuration.AUTHENTICATION_TOKEN, "<SOME API TOKEN>")
	mockConfig.Set(configuration.ORGANIZATION, uuid.New().String())
	mockConfig.Set(configuration.ORGANIZATION_SLUG, "some-org")
	mockConfig.Set(configuration.API_URL, mockServerURL)
	mockConfig.Set(configuration.INPUT_DIRECTORY, []string{"."})

	// Initialize with default values for our flags
	mockConfig.Set(flags.FlagRiskScoreThreshold, -1)
	mockConfig.Set(flags.FlagFile, "test-file.txt") // Add default test file

	mockLogger := zerolog.Nop()

	icontext := mocks.NewMockInvocationContext(ctrl)
	icontext.EXPECT().GetConfiguration().Return(mockConfig).AnyTimes()
	icontext.EXPECT().GetEnhancedLogger().Return(&mockLogger).AnyTimes()
	icontext.EXPECT().GetNetworkAccess().Return(networking.NewNetworkAccess(mockConfig)).AnyTimes()
	icontext.EXPECT().GetWorkflowIdentifier().Return(workflow.NewWorkflowIdentifier("test")).AnyTimes()
	icontext.EXPECT().GetUserInterface().Return(ui.DefaultUi()).AnyTimes()

	if engine != nil {
		icontext.EXPECT().GetEngine().Return(engine).AnyTimes()
	} else {
		icontext.EXPECT().GetEngine().Return(nil).AnyTimes()
	}

	// Mock network access
	mockNetwork := mocks.NewMockNetworkAccess(ctrl)
	mockNetwork.EXPECT().GetHttpClient().Return(&http.Client{}).AnyTimes()
	icontext.EXPECT().GetNetworkAccess().Return(mockNetwork).AnyTimes()
	icontext.EXPECT().GetAnalytics().Return(analytics.New()).AnyTimes()

	return icontext
}

// mockAPIState holds the state for the mock API server.
type mockAPIState struct {
	t           *testing.T
	mu          sync.Mutex
	server      *httptest.Server
	jobToTestID map[string]string
	testStates  map[string]*testRunState
}

// testRunState holds the state for a single test run.
type testRunState struct {
	jobID  string
	testID string
	polls  int
}

// newMockAPIState creates a new mockAPIState.
func newMockAPIState(t *testing.T) *mockAPIState {
	t.Helper()
	s := &mockAPIState{
		t:           t,
		jobToTestID: make(map[string]string),
		testStates:  make(map[string]*testRunState),
	}
	s.server = httptest.NewServer(s)
	return s
}

// Close closes the mock server.
func (s *mockAPIState) Close() {
	s.server.Close()
}

// URL returns the mock server's URL.
func (s *mockAPIState) URL() string {
	return s.server.URL
}

// ServeHTTP is the main handler for the mock server.
func (s *mockAPIState) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch {
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/tests"):
		s.handleCreateTest(w, r)
	case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/test_jobs/"):
		s.handlePollJob(w, r)
	case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/tests/") && !strings.HasSuffix(r.URL.Path, "/findings"):
		s.handleGetTestResult(w, r)
	case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/findings"):
		s.handleGetFindings(w, r)
	case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/settings/opensource"):
		s.handleGetSettings(w, r)
	default:
		http.Error(w, "unhandled request: "+r.Method+" "+r.URL.Path, http.StatusNotFound)
	}
}

func (s *mockAPIState) handleGetSettings(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/vnd.api+json")
	w.WriteHeader(http.StatusOK)
	respBody := `{
			"jsonapi": {"version": "1.0"},
			"data": {
				"type": "opensource_settings",
				"attributes": {
					"reachability": {
						"enabled": true
					}
				}
			}
		}`
	_, err := w.Write([]byte(respBody))
	require.NoError(s.t, err)
}

func (s *mockAPIState) handleCreateTest(w http.ResponseWriter, _ *http.Request) {
	jobID := uuid.New()
	testID := uuid.New()

	state := &testRunState{
		jobID:  jobID.String(),
		testID: testID.String(),
		polls:  0,
	}
	s.jobToTestID[jobID.String()] = testID.String()
	s.testStates[testID.String()] = state

	w.Header().Set("Content-Type", "application/vnd.api+json")
	w.WriteHeader(http.StatusAccepted)
	respBody := fmt.Sprintf(`{
		"jsonapi": {"version": "1.0"},
		"data": {
			"type": "test_jobs",
			"id": "%s",
			"attributes": {"status": "pending"}
		}
	}`, jobID)
	_, err := w.Write([]byte(respBody))
	require.NoError(s.t, err)
}

func (s *mockAPIState) handlePollJob(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	jobID := parts[len(parts)-1]
	testID, ok := s.jobToTestID[jobID]
	if !ok {
		http.Error(w, "job not found", http.StatusNotFound)
		return
	}
	state := s.testStates[testID]
	state.polls++

	if state.polls > 1 { // On second poll, redirect
		location := s.server.URL + "/orgs/some-org/tests/" + testID
		w.Header().Set("Location", location)
		w.Header().Set("Content-Type", "application/vnd.api+json")
		w.WriteHeader(http.StatusSeeOther)
		respBody := fmt.Sprintf(`{
			"jsonapi": {"version": "1.0"},
			"data": {
				"type": "test_jobs",
				"id": "%s",
				"attributes": {"status": "finished"},
				"relationships": {
					"test": {
						"data": { "type": "tests", "id": "%s" }
					}
				}
			},
			"links": { "related": "%s" }
		}`, jobID, testID, location)
		_, err := w.Write([]byte(respBody))
		require.NoError(s.t, err)
		return
	}

	w.Header().Set("Content-Type", "application/vnd.api+json")
	w.WriteHeader(http.StatusOK)
	respBody := fmt.Sprintf(`{
		"jsonapi": {"version": "1.0"},
		"data": {
			"type": "test_jobs",
			"id": "%s",
			"attributes": {"status": "pending"}
		}
	}`, jobID)
	_, err := w.Write([]byte(respBody))
	require.NoError(s.t, err)
}

func (s *mockAPIState) handleGetTestResult(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	testID := parts[len(parts)-1]
	if _, ok := s.testStates[testID]; !ok {
		http.Error(w, "test not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/vnd.api+json")
	w.WriteHeader(http.StatusOK)
	pass := testapi.Pass
	parsedTestID := uuid.MustParse(testID)
	testData := testapi.TestData{
		Id:   &parsedTestID,
		Type: testapi.TestDataTypeTests,
		Attributes: testapi.TestAttributes{
			State:            &testapi.TestState{Execution: testapi.TestExecutionStatesFinished},
			Outcome:          &testapi.TestOutcome{Result: pass},
			RawSummary:       &testapi.FindingSummary{Count: 0},
			EffectiveSummary: &testapi.FindingSummary{Count: 0},
			Subject:          testapi.TestSubject{},
		},
	}
	err := json.NewEncoder(w).Encode(struct {
		Data    testapi.TestData               `json:"data"`
		Jsonapi testapi.IoSnykApiCommonJsonApi `json:"jsonapi"`
	}{Data: testData, Jsonapi: testapi.IoSnykApiCommonJsonApi{Version: "1.0"}})
	require.NoError(s.t, err)
}

func (s *mockAPIState) handleGetFindings(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/vnd.api+json")
	w.WriteHeader(http.StatusOK)
	_, err := w.Write([]byte(`{"jsonapi":{"version":"1.0"},"data":[]}`))
	require.NoError(s.t, err)
}

// TestOSWorkflow_MultipleProjects_UnifiedFlow tests the behavior of the OS worfklow
// when multiple projects are being tested.
// It verifies that multiple dependency graphs are processed and their results are aggregated.
func TestOSWorkflow_MultipleProjects_UnifiedFlow(t *testing.T) {
	// Setup
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAPI := newMockAPIState(t)
	defer mockAPI.Close()

	// Mock depgraph workflow to return two depgraphs
	depGraph1Bytes, err := json.Marshal(testapi.IoSnykApiV1testdepgraphRequestDepGraph{
		SchemaVersion: "1.2.0",
		PkgManager:    testapi.IoSnykApiV1testdepgraphRequestPackageManager{Name: "npm"},
		Pkgs: []testapi.IoSnykApiV1testdepgraphRequestPackage{
			{Id: "proj1@1.0.0", Info: testapi.IoSnykApiV1testdepgraphRequestPackageInfo{Name: "proj1", Version: "1.0.0"}},
		},
		Graph: testapi.IoSnykApiV1testdepgraphRequestGraph{
			RootNodeId: "root",
			Nodes: []testapi.IoSnykApiV1testdepgraphRequestNode{
				{NodeId: "root", PkgId: "proj1@1.0.0", Deps: []testapi.IoSnykApiV1testdepgraphRequestNodeRef{}},
			},
		},
	})
	require.NoError(t, err)
	depGraph2Bytes, err := json.Marshal(testapi.IoSnykApiV1testdepgraphRequestDepGraph{
		SchemaVersion: "1.2.0",
		PkgManager:    testapi.IoSnykApiV1testdepgraphRequestPackageManager{Name: "maven"},
		Pkgs: []testapi.IoSnykApiV1testdepgraphRequestPackage{
			{Id: "proj2@2.0.0", Info: testapi.IoSnykApiV1testdepgraphRequestPackageInfo{Name: "proj2", Version: "2.0.0"}},
		},
		Graph: testapi.IoSnykApiV1testdepgraphRequestGraph{
			RootNodeId: "root",
			Nodes: []testapi.IoSnykApiV1testdepgraphRequestNode{
				{NodeId: "root", PkgId: "proj2@2.0.0", Deps: []testapi.IoSnykApiV1testdepgraphRequestNodeRef{}},
			},
		},
	})
	require.NoError(t, err)

	mockData1 := mocks.NewMockData(ctrl)
	mockData1.EXPECT().GetPayload().Return(depGraph1Bytes).AnyTimes()
	mockData1.EXPECT().GetMetaData(common.NormalisedTargetFileKey).Return("proj1/package.json", nil).AnyTimes()
	mockData1.EXPECT().GetMetaData(common.TargetFileFromPluginKey).Return("package.json", nil).AnyTimes()
	mockData1.EXPECT().GetMetaData(common.TargetKey).Return("{}", nil).AnyTimes()

	mockData2 := mocks.NewMockData(ctrl)
	mockData2.EXPECT().GetPayload().Return(depGraph2Bytes).AnyTimes()
	mockData2.EXPECT().GetMetaData(common.NormalisedTargetFileKey).Return("proj2/pom.xml", nil).AnyTimes()
	mockData2.EXPECT().GetMetaData(common.TargetFileFromPluginKey).Return("pom.xml", nil).AnyTimes()
	mockData2.EXPECT().GetMetaData(common.TargetKey).Return("{}", nil).AnyTimes()

	dir := createTempLegacyPolicy(t, `
version: v1.0.0
ignore: {}
`)

	tcs := map[string]struct {
		setupTest func(workflow.InvocationContext, *mocks.MockEngine)
	}{
		"--all-projects": {
			setupTest: func(ictx workflow.InvocationContext, engine *mocks.MockEngine) {
				config := ictx.GetConfiguration()
				config.Set(constants.FeatureFlagRiskScore, true)
				config.Set(constants.FeatureFlagRiskScoreInCLI, true)
				config.Set(outputworkflow.OutputConfigKeyJSON, true)

				config.Set(flags.FlagAllProjects, true)
				config.Set(flags.FlagPolicyPath, dir)

				depGraphs := []workflow.Data{mockData1, mockData2}
				engine.EXPECT().
					InvokeWithConfig(common.DepGraphWorkflowID, gomock.Any()).
					Return(depGraphs, nil).
					Times(1)
			},
		},
		"multiple paths": {
			setupTest: func(ictx workflow.InvocationContext, engine *mocks.MockEngine) {
				config := ictx.GetConfiguration()
				config.Set(constants.FeatureFlagRiskScore, true)
				config.Set(constants.FeatureFlagRiskScoreInCLI, true)
				config.Set(outputworkflow.OutputConfigKeyJSON, true)
				config.Set(flags.FlagPolicyPath, dir)

				config.Set(configuration.INPUT_DIRECTORY, []string{".", "."})

				depGraph1 := []workflow.Data{mockData1}
				engine.EXPECT().
					InvokeWithConfig(common.DepGraphWorkflowID, gomock.Any()).
					Return(depGraph1, nil)

				depGraph2 := []workflow.Data{mockData2}
				engine.EXPECT().
					InvokeWithConfig(common.DepGraphWorkflowID, gomock.Any()).
					Return(depGraph2, nil)
			},
		},
	}

	for tcName, tcs := range tcs {
		t.Run(tcName, func(t *testing.T) {
			mockEngine := mocks.NewMockEngine(ctrl)
			mockInvocationCtx := createMockInvocationCtxWithURL(t, ctrl, mockEngine, mockAPI.URL())
			tcs.setupTest(mockInvocationCtx, mockEngine)

			// Temporarily reduce the poll interval for this test to avoid timeouts.
			originalPollInterval := ostest.PollInterval
			ostest.PollInterval = testapi.MinPollInterval
			t.Cleanup(func() { ostest.PollInterval = originalPollInterval })

			// Execute
			results, err := ostest.OSWorkflow(mockInvocationCtx, []workflow.Data{})

			// Verify
			require.NoError(t, err)
			require.NotEmpty(t, results)

			var jsonOutputs []workflow.Data
			var summaryOutputs []workflow.Data
			for _, r := range results {
				if r.GetContentType() == ostest.ApplicationJSONContentType {
					jsonOutputs = append(jsonOutputs, r)
				} else if r.GetContentType() == content_type.TEST_SUMMARY {
					summaryOutputs = append(summaryOutputs, r)
				}
			}

			// Should have 1 JSON output (as an array of results) and 2 summary outputs (no findings, empty summaries)
			assert.Len(t, jsonOutputs, 1)
			assert.Len(t, summaryOutputs, 2)

			// Verify JSON output is an array of 2 results
			var legacyResults []definitions.LegacyVulnerabilityResponse
			payload, ok := jsonOutputs[0].GetPayload().([]byte)
			require.True(t, ok, "Payload is not of type []byte")
			unmarshalErr := json.Unmarshal(payload, &legacyResults)
			require.NoError(t, unmarshalErr, "Failed to unmarshal legacy vulnerability responses")
			assert.Len(t, legacyResults, 2)

			assert.Equal(t, "package.json", *legacyResults[0].TargetFile)
			assert.Equal(t, "pom.xml", *legacyResults[1].TargetFile)

			assert.True(t, legacyResults[0].FilesystemPolicy)
			assert.True(t, legacyResults[1].FilesystemPolicy)

			// The order is not guaranteed, so we check for presence
			projectNames := []string{legacyResults[0].ProjectName, legacyResults[1].ProjectName}
			assert.Contains(t, projectNames, "proj1")
			assert.Contains(t, projectNames, "proj2")
		})
	}
}

func TestOSWorkflow_ReachabilityFilterValidation(t *testing.T) {
	tests := []struct {
		name          string
		setup         func(config configuration.Configuration)
		expectError   bool
		errorContains string
	}{
		{
			name: "reachability-filter without reachability flag - should error",
			setup: func(config configuration.Configuration) {
				config.Set(flags.FlagReachabilityFilter, "reachable")
				config.Set(flags.FlagReachability, false)
			},
			expectError: true,
		},
		{
			name: "reachability-filter with sbom but without reachability flag - should error",
			setup: func(config configuration.Configuration) {
				config.Set(flags.FlagReachabilityFilter, "no-path-found")
				config.Set(flags.FlagSBOM, "bom.json")
				config.Set(flags.FlagReachability, false)
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockAPI := newMockAPIState(t)
			defer mockAPI.Close()

			mockEngine := mocks.NewMockEngine(ctrl)
			mockInvocationCtx := createMockInvocationCtxWithURL(t, ctrl, mockEngine, mockAPI.URL())

			tt.setup(mockInvocationCtx.GetConfiguration())

			_, err := ostest.OSWorkflow(mockInvocationCtx, []workflow.Data{})

			if tt.expectError {
				require.Error(t, err)
				assert.ErrorContains(t, err, "Invalid flag option")
			}
		})
	}
}

func createTempLegacyPolicy(t *testing.T, policy string) string {
	t.Helper()

	dir := t.TempDir()
	fd, err := os.Create(filepath.Join(dir, ".snyk"))
	require.NoError(t, err)
	defer fd.Close()

	_, err = fd.WriteString(policy)
	require.NoError(t, err)

	return dir
}
