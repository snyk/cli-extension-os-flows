package common_test

import (
	"math"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	snyk_errors "github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/snyk/go-application-framework/pkg/analytics"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/networking"
	"github.com/snyk/go-application-framework/pkg/ui"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	"github.com/snyk/cli-extension-os-flows/internal/common"
	"github.com/snyk/cli-extension-os-flows/internal/errors"
	"github.com/snyk/cli-extension-os-flows/internal/util"
	"github.com/snyk/cli-extension-os-flows/pkg/flags"
)

var (
	policyTestLogger     = zerolog.Nop()
	policyTestErrFactory = errors.NewErrorFactory(&policyTestLogger)
)

type nopProgressBar struct{}

func (npb *nopProgressBar) SetTitle(_ string)                                    {}
func (npb *nopProgressBar) UpdateProgress(_ float64) error                       { return nil }
func (npb *nopProgressBar) Clear() error                                         { return nil }
func (npb *nopProgressBar) SetCompletionMessage(_ string)                        {}
func (npb *nopProgressBar) SetCompletionMessageWithStyle(_, _ string)            {}
func (npb *nopProgressBar) SetCompletionMessageWithTitle(_, _ string)            {}
func (npb *nopProgressBar) SetCompletionMessageWithTitleAndStyle(_, _, _ string) {}

func createMockInvocationCtx(t *testing.T, ctrl *gomock.Controller) workflow.InvocationContext {
	t.Helper()

	mockConfig := configuration.New()
	mockConfig.Set(configuration.AUTHENTICATION_TOKEN, "<SOME API TOKEN>")
	mockConfig.Set(configuration.ORGANIZATION, "some-org-id")
	mockConfig.Set(configuration.ORGANIZATION_SLUG, "some-org")
	mockConfig.Set(configuration.INPUT_DIRECTORY, []string{"."})
	mockConfig.Set(flags.FlagRiskScoreThreshold, -1)

	mockLogger := zerolog.Nop()

	icontext := mocks.NewMockInvocationContext(ctrl)
	icontext.EXPECT().GetConfiguration().Return(mockConfig).AnyTimes()
	icontext.EXPECT().GetEnhancedLogger().Return(&mockLogger).AnyTimes()
	icontext.EXPECT().GetNetworkAccess().Return(networking.NewNetworkAccess(mockConfig)).AnyTimes()
	icontext.EXPECT().GetWorkflowIdentifier().Return(workflow.NewWorkflowIdentifier("test")).AnyTimes()
	icontext.EXPECT().GetUserInterface().Return(ui.DefaultUi()).AnyTimes()
	icontext.EXPECT().GetEngine().Return(nil).AnyTimes()

	mockNetwork := mocks.NewMockNetworkAccess(ctrl)
	mockNetwork.EXPECT().GetHttpClient().Return(&http.Client{}).AnyTimes()
	icontext.EXPECT().GetNetworkAccess().Return(mockNetwork).AnyTimes()
	icontext.EXPECT().GetAnalytics().Return(analytics.New()).AnyTimes()

	return icontext
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

func TestCreateLocalPolicy(t *testing.T) {
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

	pb := &nopProgressBar{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockInvocationCtx := createMockInvocationCtx(t, ctrl)
			mockConfig := mockInvocationCtx.GetConfiguration()

			mockConfig.Set(flags.FlagRiskScoreThreshold, 100)
			mockConfig.Set(flags.FlagSeverityThreshold, "high")

			ctx := t.Context()
			ctx = cmdctx.WithIctx(ctx, mockInvocationCtx)
			ctx = cmdctx.WithConfig(ctx, mockConfig)
			ctx = cmdctx.WithLogger(ctx, &policyTestLogger)
			ctx = cmdctx.WithErrorFactory(ctx, policyTestErrFactory)
			ctx = cmdctx.WithProgressBar(ctx, pb)

			if tt.setFailOnFlag {
				mockConfig.Set(flags.FlagFailOn, tt.failOnValue)
			}

			localPolicy, err := common.CreateLocalPolicy(ctx, ".")
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

func TestCreateLocalPolicy_UnsupportedFailOnValue(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockInvocationCtx := createMockInvocationCtx(t, ctrl)
	mockConfig := mockInvocationCtx.GetConfiguration()

	mockConfig.Set(flags.FlagFailOn, "unsupported")

	ctx := t.Context()
	ctx = cmdctx.WithIctx(ctx, mockInvocationCtx)
	ctx = cmdctx.WithConfig(ctx, mockConfig)
	ctx = cmdctx.WithLogger(ctx, &policyTestLogger)
	ctx = cmdctx.WithErrorFactory(ctx, policyTestErrFactory)
	ctx = cmdctx.WithProgressBar(ctx, &nopProgressBar{})

	localPolicy, err := common.CreateLocalPolicy(ctx, ".")
	require.Error(t, err)
	assert.Nil(t, localPolicy)
	var catalogErr snyk_errors.Error
	require.ErrorAs(t, err, &catalogErr)
	assert.Contains(t, catalogErr.Detail, "Unsupported value 'unsupported' for --fail-on flag")
	assert.Contains(t, catalogErr.Detail, "Supported values are: 'all', 'upgradable'")
}

func TestCreateLocalPolicy_NoValues(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockInvocationCtx := createMockInvocationCtx(t, ctrl)
	mockConfig := mockInvocationCtx.GetConfiguration()
	ctx := t.Context()
	ctx = cmdctx.WithIctx(ctx, mockInvocationCtx)
	ctx = cmdctx.WithConfig(ctx, mockConfig)
	ctx = cmdctx.WithLogger(ctx, &policyTestLogger)
	ctx = cmdctx.WithErrorFactory(ctx, policyTestErrFactory)
	ctx = cmdctx.WithProgressBar(ctx, &nopProgressBar{})

	localPolicy, err := common.CreateLocalPolicy(ctx, ".")
	require.NoError(t, err)

	assert.Nil(t, localPolicy)
}

func TestCreateLocalPolicy_RiskScoreOverflow(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockInvocationCtx := createMockInvocationCtx(t, ctrl)
	mockConfig := mockInvocationCtx.GetConfiguration()
	mockConfig.Set(flags.FlagRiskScoreThreshold, math.MaxUint16+10)
	ctx := t.Context()
	ctx = cmdctx.WithIctx(ctx, mockInvocationCtx)
	ctx = cmdctx.WithConfig(ctx, mockConfig)
	ctx = cmdctx.WithLogger(ctx, &policyTestLogger)
	ctx = cmdctx.WithErrorFactory(ctx, policyTestErrFactory)
	ctx = cmdctx.WithProgressBar(ctx, &nopProgressBar{})

	localPolicy, err := common.CreateLocalPolicy(ctx, ".")
	require.NoError(t, err)
	require.NotNil(t, localPolicy)

	assert.NotNil(t, localPolicy.RiskScoreThreshold)
	assert.Equal(t, uint16(math.MaxUint16), *localPolicy.RiskScoreThreshold)
}

func TestCreateLocalPolicy_SeverityThresholdDefaultsToNone(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockInvocationCtx := createMockInvocationCtx(t, ctrl)
	mockConfig := mockInvocationCtx.GetConfiguration()

	mockConfig.Set(flags.FlagRiskScoreThreshold, 100)
	mockConfig.Set(flags.FlagSeverityThreshold, "")
	ctx := t.Context()
	ctx = cmdctx.WithIctx(ctx, mockInvocationCtx)
	ctx = cmdctx.WithConfig(ctx, mockConfig)
	ctx = cmdctx.WithLogger(ctx, &policyTestLogger)
	ctx = cmdctx.WithErrorFactory(ctx, policyTestErrFactory)
	ctx = cmdctx.WithProgressBar(ctx, &nopProgressBar{})

	localPolicy, err := common.CreateLocalPolicy(ctx, ".")
	require.NoError(t, err)
	require.NotNil(t, localPolicy)

	require.NotNil(t, localPolicy.RiskScoreThreshold)
	assert.Equal(t, uint16(100), *localPolicy.RiskScoreThreshold)

	require.NotNil(t, localPolicy.SeverityThreshold)
	assert.Equal(t, testapi.SeverityNone, *localPolicy.SeverityThreshold)
}

func TestCreateLocalPolicy_ReachabilityFilterDefaultBehavior(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockInvocationCtx := createMockInvocationCtx(t, ctrl)
	mockConfig := mockInvocationCtx.GetConfiguration()

	mockConfig.Set(flags.FlagRiskScoreThreshold, 100)
	mockConfig.Set(flags.FlagReachabilityFilter, "")
	ctx := t.Context()
	ctx = cmdctx.WithIctx(ctx, mockInvocationCtx)
	ctx = cmdctx.WithConfig(ctx, mockConfig)
	ctx = cmdctx.WithLogger(ctx, &policyTestLogger)
	ctx = cmdctx.WithErrorFactory(ctx, policyTestErrFactory)
	ctx = cmdctx.WithProgressBar(ctx, &nopProgressBar{})

	localPolicy, err := common.CreateLocalPolicy(ctx, ".")
	require.NoError(t, err)
	require.NotNil(t, localPolicy)

	require.NotNil(t, localPolicy.RiskScoreThreshold)
	assert.Equal(t, uint16(100), *localPolicy.RiskScoreThreshold)

	require.NotNil(t, localPolicy.SeverityThreshold)
	assert.Equal(t, testapi.SeverityNone, *localPolicy.SeverityThreshold)

	assert.Nil(t, localPolicy.ReachabilityFilter)
}

func TestCreateLocalPolicy_ReachabilityFilter(t *testing.T) {
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
			ctx = cmdctx.WithLogger(ctx, &policyTestLogger)
			ctx = cmdctx.WithErrorFactory(ctx, policyTestErrFactory)
			ctx = cmdctx.WithProgressBar(ctx, &nopProgressBar{})

			localPolicy, err := common.CreateLocalPolicy(ctx, ".")
			require.NoError(t, err)
			assert.Equal(t, tt.expectFilter, localPolicy.ReachabilityFilter != nil)

			if tt.expectFilter {
				assert.Equal(t, tt.expectedValue, *localPolicy.ReachabilityFilter)
			}
		})
	}
}

func TestCreateLocalPolicy_NoLegacyPolicy(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockInvocationCtx := createMockInvocationCtx(t, ctrl)
	mockConfig := mockInvocationCtx.GetConfiguration()
	mockConfig.Set(flags.FlagRiskScoreThreshold, 100)
	ctx := t.Context()
	ctx = cmdctx.WithIctx(ctx, mockInvocationCtx)
	ctx = cmdctx.WithConfig(ctx, mockConfig)
	ctx = cmdctx.WithLogger(ctx, &policyTestLogger)
	ctx = cmdctx.WithErrorFactory(ctx, policyTestErrFactory)
	ctx = cmdctx.WithProgressBar(ctx, &nopProgressBar{})

	localPolicy, _ := common.CreateLocalPolicy(ctx, ".")
	require.NotNil(t, localPolicy)
	assert.Nil(t, localPolicy.Ignores)
}

func TestCreateLocalPolicy_WithLegacyPolicy(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockInvocationCtx := createMockInvocationCtx(t, ctrl)
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
	ctx = cmdctx.WithLogger(ctx, &policyTestLogger)
	ctx = cmdctx.WithErrorFactory(ctx, policyTestErrFactory)
	ctx = cmdctx.WithProgressBar(ctx, &nopProgressBar{})

	localPolicy, _ := common.CreateLocalPolicy(ctx, dir)
	require.NotNil(t, localPolicy)
	require.NotNil(t, localPolicy.Ignores)
	assert.Len(t, *localPolicy.Ignores, 1)
}

func TestCreateLocalPolicy_PointingAtLegacyPolicy(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockInvocationCtx := createMockInvocationCtx(t, ctrl)
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
	ctx = cmdctx.WithLogger(ctx, &policyTestLogger)
	ctx = cmdctx.WithErrorFactory(ctx, policyTestErrFactory)
	ctx = cmdctx.WithProgressBar(ctx, &nopProgressBar{})

	localPolicy, _ := common.CreateLocalPolicy(ctx, ".")
	require.NotNil(t, localPolicy)
	require.NotNil(t, localPolicy.Ignores)
	assert.Len(t, *localPolicy.Ignores, 1)
}
