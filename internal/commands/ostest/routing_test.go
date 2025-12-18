package ostest_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"
	snyk_errors "github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/pkg/flags"

	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	"github.com/snyk/cli-extension-os-flows/internal/commands/ostest"
	"github.com/snyk/cli-extension-os-flows/internal/constants"
	"github.com/snyk/cli-extension-os-flows/internal/settings"
	"github.com/snyk/cli-extension-os-flows/internal/util"
)

var (
	orgID                            = uuid.MustParse("0fc7ac6a-bd21-4434-a8f1-6088626eb32f")
	orgIDWithoutReachabilitySettings = uuid.MustParse("24944260-6317-4bad-a57e-77a236c0f773")
	orgIDWithReachabilitySettingsErr = uuid.MustParse("918cb032-7ee5-493e-9f3a-91465445af89")
)

func setupSettingsClient(t *testing.T) settings.Client {
	t.Helper()
	sc := settings.NewFakeClient(map[settings.OrgID]struct {
		IsEnabled bool
		Err       error
	}{
		orgID: {
			IsEnabled: true,
		},
		orgIDWithoutReachabilitySettings: {
			IsEnabled: false,
		},
		orgIDWithReachabilitySettingsErr: {
			Err: assert.AnError,
		},
	})

	return sc
}

func Test_ShouldUseLegacyFlow(t *testing.T) {
	t.Parallel()
	defaultConfig := configuration.New()
	defaultConfig.Set(flags.FlagRiskScoreThreshold, -1)
	newOptions := map[string]func(configuration.Configuration) configuration.Configuration{
		"--reachability": func(cfg configuration.Configuration) configuration.Configuration {
			newCfg := cfg.Clone()
			newCfg.Set(flags.FlagReachability, true)
			return newCfg
		},
		"--reachability-filter": func(cfg configuration.Configuration) configuration.Configuration {
			newCfg := cfg.Clone()
			newCfg.Set(flags.FlagReachabilityFilter, "reachable")
			return newCfg
		},
		"--reachability and --sbom": func(cfg configuration.Configuration) configuration.Configuration {
			newCfg := cfg.Clone()
			newCfg.Set(flags.FlagReachability, true)
			newCfg.Set(flags.FlagSBOM, "sbom.json")
			return newCfg
		},
		"--sbom": func(cfg configuration.Configuration) configuration.Configuration {
			newCfg := cfg.Clone()
			newCfg.Set(flags.FlagSBOM, "sbom.json")
			return newCfg
		},

		"--risk-score-threshold": func(cfg configuration.Configuration) configuration.Configuration {
			newCfg := cfg.Clone()
			newCfg.Set(flags.FlagRiskScoreThreshold, 100)
			return newCfg
		},
	}

	t.Run("when env var is set", func(t *testing.T) {
		t.Parallel()
		cfg := defaultConfig.Clone()
		cfg.Set(constants.ForceLegacyCLIEnvVar, true)

		ctx := t.Context()
		ctx = cmdctx.WithConfig(ctx, cfg)
		ctx = cmdctx.WithLogger(ctx, &nopLogger)
		ctx = cmdctx.WithErrorFactory(ctx, errFactory)

		flowCfg, err := ostest.ParseFlowConfig(cfg)
		require.NoError(t, err)
		useLegacy, err := ostest.ShouldUseLegacyFlow(ctx, flowCfg, []string{"."})
		require.NoError(t, err)

		assert.True(t, useLegacy)

		for name, newOption := range newOptions {
			t.Run(fmt.Sprintf("should fail when %s is/are set", name), func(t *testing.T) {
				t.Parallel()
				testCfg := newOption(cfg.Clone())
				ctx := t.Context()
				ctx = cmdctx.WithConfig(ctx, testCfg)
				ctx = cmdctx.WithLogger(ctx, &nopLogger)
				ctx = cmdctx.WithErrorFactory(ctx, errFactory)

				flowCfg, err := ostest.ParseFlowConfig(testCfg)
				require.NoError(t, err)
				_, err = ostest.ShouldUseLegacyFlow(ctx, flowCfg, []string{"."})

				assert.Error(t, err)
			})
		}
	})

	t.Run("when legacy options are set", func(t *testing.T) {
		t.Parallel()
		legacyOptions := []string{flags.FlagPrintGraph, flags.FlagPrintDeps, flags.FlagPrintDepPaths, flags.FlagUnmanaged}
		for _, legacyOption := range legacyOptions {
			cfg := defaultConfig.Clone()
			cfg.Set(legacyOption, true)

			t.Run(fmt.Sprintf("--%s should route to legacy command", legacyOption), func(t *testing.T) {
				t.Parallel()
				testCfg := cfg.Clone()
				ctx := t.Context()
				ctx = cmdctx.WithConfig(ctx, testCfg)
				ctx = cmdctx.WithLogger(ctx, &nopLogger)
				ctx = cmdctx.WithErrorFactory(ctx, errFactory)

				flowCfg, err := ostest.ParseFlowConfig(testCfg)
				require.NoError(t, err)
				useLegacy, err := ostest.ShouldUseLegacyFlow(ctx, flowCfg, []string{"."})
				require.NoError(t, err)

				assert.True(t, useLegacy)
			})

			for name, newOption := range newOptions {
				t.Run(fmt.Sprintf("should fail when %s is/are set", name), func(t *testing.T) {
					t.Parallel()
					testCfg := newOption(cfg.Clone())
					ctx := t.Context()
					ctx = cmdctx.WithConfig(ctx, testCfg)
					ctx = cmdctx.WithLogger(ctx, &nopLogger)
					ctx = cmdctx.WithErrorFactory(ctx, errFactory)

					flowCfg, err := ostest.ParseFlowConfig(testCfg)
					require.NoError(t, err)
					_, err = ostest.ShouldUseLegacyFlow(ctx, flowCfg, []string{"."})

					assert.Error(t, err)
				})
			}
		}
	})

	t.Run("when --unmanaged and --reachability are set", func(t *testing.T) {
		t.Parallel()
		cfg := defaultConfig.Clone()
		cfg.Set(flags.FlagUnmanaged, true)
		cfg.Set(flags.FlagReachability, true)

		ctx := t.Context()
		ctx = cmdctx.WithConfig(ctx, cfg)
		ctx = cmdctx.WithLogger(ctx, &nopLogger)
		ctx = cmdctx.WithErrorFactory(ctx, errFactory)

		flowCfg, err := ostest.ParseFlowConfig(cfg)
		require.NoError(t, err)
		_, err = ostest.ShouldUseLegacyFlow(ctx, flowCfg, []string{"."})
		require.Error(t, err)
		var catalogErr snyk_errors.Error
		require.ErrorAs(t, err, &catalogErr)
		assert.Equal(t, "The options --reachability, --unmanaged cannot be used together.", catalogErr.Detail)
	})

	t.Run("when multiple invalid flags are set", func(t *testing.T) {
		t.Parallel()
		cfg := defaultConfig.Clone()
		cfg.Set(constants.ForceLegacyCLIEnvVar, true)
		cfg.Set(flags.FlagReachability, true)
		cfg.Set(flags.FlagSBOM, "sbom.json")
		cfg.Set(flags.FlagRiskScoreThreshold, 100)

		ctx := t.Context()
		ctx = cmdctx.WithConfig(ctx, cfg)
		ctx = cmdctx.WithLogger(ctx, &nopLogger)
		ctx = cmdctx.WithErrorFactory(ctx, errFactory)

		flowCfg, err := ostest.ParseFlowConfig(cfg)
		require.NoError(t, err)
		_, err = ostest.ShouldUseLegacyFlow(ctx, flowCfg, []string{"."})
		require.Error(t, err)
		var catalogErr snyk_errors.Error
		require.ErrorAs(t, err, &catalogErr)
		assert.Equal(t, "The options --reachability, --risk-score-threshold, --sbom cannot be used together.", catalogErr.Detail)
	})

	t.Run("when no new options are provided", func(t *testing.T) {
		t.Parallel()
		cfg := defaultConfig.Clone()

		ctx := t.Context()
		ctx = cmdctx.WithConfig(ctx, cfg)
		ctx = cmdctx.WithLogger(ctx, &nopLogger)
		ctx = cmdctx.WithErrorFactory(ctx, errFactory)

		flowCfg, err := ostest.ParseFlowConfig(cfg)
		require.NoError(t, err)
		useLegacy, err := ostest.ShouldUseLegacyFlow(ctx, flowCfg, []string{"."})
		require.NoError(t, err)

		assert.True(t, useLegacy)
	})

	t.Run("when a package name is provided", func(t *testing.T) {
		t.Parallel()
		cfg := defaultConfig.Clone()
		cfg.Set(configuration.INPUT_DIRECTORY, []string{"lodash@1.2.3"})

		ctx := t.Context()
		ctx = cmdctx.WithConfig(ctx, cfg)
		ctx = cmdctx.WithLogger(ctx, &nopLogger)
		ctx = cmdctx.WithErrorFactory(ctx, errFactory)

		flowCfg, err := ostest.ParseFlowConfig(cfg)
		require.NoError(t, err)
		useLegacy, err := ostest.ShouldUseLegacyFlow(ctx, flowCfg, []string{"."})
		require.NoError(t, err)

		assert.True(t, useLegacy)
	})

	t.Run("when a package name and a new option is provided", func(t *testing.T) {
		t.Parallel()
		cfg := defaultConfig.Clone()
		cfg.Set(configuration.INPUT_DIRECTORY, []string{"lodash@1.2.3"})
		cfg.Set(flags.FlagReachability, true)

		ctx := t.Context()
		ctx = cmdctx.WithConfig(ctx, cfg)
		ctx = cmdctx.WithLogger(ctx, &nopLogger)
		ctx = cmdctx.WithErrorFactory(ctx, errFactory)

		flowCfg, err := ostest.ParseFlowConfig(cfg)
		require.NoError(t, err)
		_, err = ostest.ShouldUseLegacyFlow(ctx, flowCfg, []string{"."})
		require.Error(t, err)

		var catalogErr snyk_errors.Error
		require.ErrorAs(t, err, &catalogErr)
		assert.Equal(t, "The argument 'lodash@1.2.3' cannot be combined with flags --reachability.", catalogErr.Detail)
	})

	t.Run("when UV support is enabled with uv.lock file present and experimental flag set", func(t *testing.T) {
		t.Parallel()
		cfg := defaultConfig.Clone()
		cfg.Set(configuration.FLAG_EXPERIMENTAL, true)
		cfg.Set(constants.EnableExperimentalUvSupportEnvVar, true)

		// Create temp directory with uv.lock file
		tempDir := util.CreateTempDirWithUvLock(t)
		cfg.Set(configuration.INPUT_DIRECTORY, []string{tempDir})

		ctx := t.Context()
		ctx = cmdctx.WithConfig(ctx, cfg)
		ctx = cmdctx.WithLogger(ctx, &nopLogger)
		ctx = cmdctx.WithErrorFactory(ctx, errFactory)

		flowCfg, err := ostest.ParseFlowConfig(cfg)
		require.NoError(t, err)
		useLegacy, err := ostest.ShouldUseLegacyFlow(ctx, flowCfg, []string{tempDir})
		require.NoError(t, err)

		assert.False(t, useLegacy, "should use new flow when experimental flag and UV support are enabled and uv.lock exists")
	})

	t.Run("when UV support is enabled but uv.lock file is missing", func(t *testing.T) {
		t.Parallel()
		cfg := defaultConfig.Clone()
		cfg.Set(configuration.FLAG_EXPERIMENTAL, true)
		cfg.Set(constants.EnableExperimentalUvSupportEnvVar, true)

		// Create temp directory without uv.lock file
		tempDir := t.TempDir()
		cfg.Set(configuration.INPUT_DIRECTORY, []string{tempDir})

		ctx := t.Context()
		ctx = cmdctx.WithConfig(ctx, cfg)
		ctx = cmdctx.WithLogger(ctx, &nopLogger)
		ctx = cmdctx.WithErrorFactory(ctx, errFactory)

		flowCfg, err := ostest.ParseFlowConfig(cfg)
		require.NoError(t, err)
		useLegacy, err := ostest.ShouldUseLegacyFlow(ctx, flowCfg, []string{tempDir})
		require.NoError(t, err)

		assert.True(t, useLegacy, "should use legacy flow when UV support is enabled but uv.lock is missing")
	})

	t.Run("when experimental flag is not set even with UV support enabled and uv.lock present", func(t *testing.T) {
		t.Parallel()
		cfg := defaultConfig.Clone()
		cfg.Set(configuration.FLAG_EXPERIMENTAL, false)
		cfg.Set(constants.EnableExperimentalUvSupportEnvVar, true)

		// Create temp directory with uv.lock file
		tempDir := util.CreateTempDirWithUvLock(t)
		cfg.Set(configuration.INPUT_DIRECTORY, []string{tempDir})

		ctx := t.Context()
		ctx = cmdctx.WithConfig(ctx, cfg)
		ctx = cmdctx.WithLogger(ctx, &nopLogger)
		ctx = cmdctx.WithErrorFactory(ctx, errFactory)

		flowCfg, err := ostest.ParseFlowConfig(cfg)
		require.NoError(t, err)
		useLegacy, err := ostest.ShouldUseLegacyFlow(ctx, flowCfg, []string{tempDir})
		require.NoError(t, err)

		assert.True(t, useLegacy, "should use legacy flow when experimental flag is not set regardless of UV support")
	})
	t.Run("when UV support is disabled even with uv.lock present", func(t *testing.T) {
		t.Parallel()
		cfg := defaultConfig.Clone()
		cfg.Set(constants.EnableExperimentalUvSupportEnvVar, false)

		// Create temp directory with uv.lock file
		tempDir := util.CreateTempDirWithUvLock(t)
		cfg.Set(configuration.INPUT_DIRECTORY, []string{tempDir})

		ctx := t.Context()
		ctx = cmdctx.WithConfig(ctx, cfg)
		ctx = cmdctx.WithLogger(ctx, &nopLogger)
		ctx = cmdctx.WithErrorFactory(ctx, errFactory)

		flowCfg, err := ostest.ParseFlowConfig(cfg)
		require.NoError(t, err)
		useLegacy, err := ostest.ShouldUseLegacyFlow(ctx, flowCfg, []string{tempDir})
		require.NoError(t, err)

		assert.True(t, useLegacy, "should use legacy flow when UV support is disabled regardless of uv.lock presence")
	})
}

func Test_RouteToFlow_SBOMReachabilityFlow(t *testing.T) {
	t.Parallel()
	defaultConfig := configuration.New()
	defaultConfig.Set(flags.FlagRiskScoreThreshold, -1)
	sc := setupSettingsClient(t)
	tcs := map[string]struct {
		ctx                 func(context.Context) context.Context
		orgID               uuid.UUID
		expectedFlow        ostest.Flow
		expectErrorContains string
	}{
		"--reachability with --sbom should route to SBOM reachability flow when FF and reachability settings are enabled": {
			ctx: func(ctx context.Context) context.Context {
				cfg := defaultConfig.Clone()
				cfg.Set(flags.FlagSBOM, "sbom.json")
				cfg.Set(flags.FlagReachability, true)

				ctx = cmdctx.WithConfig(ctx, cfg)
				ctx = cmdctx.WithLogger(ctx, &nopLogger)
				ctx = cmdctx.WithErrorFactory(ctx, errFactory)

				return ctx
			},
			orgID:        orgID,
			expectedFlow: ostest.SbomFlow,
		},
		"--reachability with --sbom and --reachability-filter should route to SBOM reachability flow when FF and reachability settings are enabled": {
			ctx: func(ctx context.Context) context.Context {
				cfg := defaultConfig.Clone()
				cfg.Set(flags.FlagSBOM, "sbom.json")
				cfg.Set(flags.FlagReachability, true)
				cfg.Set(flags.FlagReachabilityFilter, "reachable")

				ctx = cmdctx.WithConfig(ctx, cfg)
				ctx = cmdctx.WithLogger(ctx, &nopLogger)
				ctx = cmdctx.WithErrorFactory(ctx, errFactory)

				return ctx
			},
			orgID:        orgID,
			expectedFlow: ostest.SbomFlow,
		},
		"--reachability with --sbom should fail when reachability settings are disabled": {
			ctx: func(ctx context.Context) context.Context {
				cfg := defaultConfig.Clone()
				cfg.Set(flags.FlagSBOM, "sbom.json")
				cfg.Set(flags.FlagReachability, true)

				ctx = cmdctx.WithConfig(ctx, cfg)
				ctx = cmdctx.WithLogger(ctx, &nopLogger)
				ctx = cmdctx.WithErrorFactory(ctx, errFactory)

				return ctx
			},
			orgID:               orgIDWithoutReachabilitySettings,
			expectErrorContains: "Reachability settings not enabled",
		},
		"--reachability with --sbom should fail when reachability settings check fails": {
			ctx: func(ctx context.Context) context.Context {
				cfg := defaultConfig.Clone()
				cfg.Set(flags.FlagSBOM, "sbom.json")
				cfg.Set(flags.FlagReachability, true)

				ctx = cmdctx.WithConfig(ctx, cfg)
				ctx = cmdctx.WithLogger(ctx, &nopLogger)
				ctx = cmdctx.WithErrorFactory(ctx, errFactory)

				return ctx
			},
			orgID:               orgIDWithReachabilitySettingsErr,
			expectErrorContains: "failed to check reachability settings",
		},
	}
	for tcName, tc := range tcs {
		t.Run(tcName, func(t *testing.T) {
			t.Parallel()
			ctx := tc.ctx(t.Context())
			cfg := cmdctx.Config(ctx)
			flowCfg, err := ostest.ParseFlowConfig(cfg)
			require.NoError(t, err)

			flow, err := ostest.RouteToFlow(ctx, flowCfg, tc.orgID, sc)

			if tc.expectErrorContains == "" {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedFlow, flow)
			} else {
				assert.ErrorContains(t, err, tc.expectErrorContains)
			}
		})
	}
}

func Test_RouteToFlow_ReachabilityFlow(t *testing.T) {
	t.Parallel()
	defaultConfig := configuration.New()
	defaultConfig.Set(flags.FlagRiskScoreThreshold, -1)
	sc := setupSettingsClient(t)
	tcs := map[string]struct {
		ctx                 func(context.Context) context.Context
		orgID               uuid.UUID
		expectedFlow        ostest.Flow
		expectErrorContains string
	}{
		"--reachability should route to depgraph reachability flow when FF and reachability settings are enabled": {
			ctx: func(ctx context.Context) context.Context {
				cfg := defaultConfig.Clone()
				cfg.Set(flags.FlagReachability, true)
				cfg.Set(constants.FeatureFlagReachabilityForCLI, true)

				ctx = cmdctx.WithConfig(ctx, cfg)
				ctx = cmdctx.WithLogger(ctx, &nopLogger)
				ctx = cmdctx.WithErrorFactory(ctx, errFactory)

				return ctx
			},
			orgID:        orgID,
			expectedFlow: ostest.DepgraphReachabilityFlow,
		},
		"--reachability with --reachability-filter should route to depgraph reachability flow when FF and reachability settings are enabled": {
			ctx: func(ctx context.Context) context.Context {
				cfg := defaultConfig.Clone()
				cfg.Set(flags.FlagReachability, true)
				cfg.Set(flags.FlagReachabilityFilter, "reachable")
				cfg.Set(constants.FeatureFlagReachabilityForCLI, true)

				ctx = cmdctx.WithConfig(ctx, cfg)
				ctx = cmdctx.WithLogger(ctx, &nopLogger)
				ctx = cmdctx.WithErrorFactory(ctx, errFactory)

				return ctx
			},
			orgID:        orgID,
			expectedFlow: ostest.DepgraphReachabilityFlow,
		},
		"--reachability should fail when FF is missing": {
			ctx: func(ctx context.Context) context.Context {
				cfg := defaultConfig.Clone()
				cfg.Set(flags.FlagReachability, true)

				ctx = cmdctx.WithConfig(ctx, cfg)
				ctx = cmdctx.WithLogger(ctx, &nopLogger)
				ctx = cmdctx.WithErrorFactory(ctx, errFactory)

				return ctx
			},
			orgID:               orgID,
			expectErrorContains: "Reachability settings not enabled",
		},
		"--reachability should fail when reachability settings are disabled": {
			ctx: func(ctx context.Context) context.Context {
				cfg := defaultConfig.Clone()
				cfg.Set(flags.FlagReachability, true)
				cfg.Set(constants.FeatureFlagReachabilityForCLI, true)

				ctx = cmdctx.WithConfig(ctx, cfg)
				ctx = cmdctx.WithLogger(ctx, &nopLogger)
				ctx = cmdctx.WithErrorFactory(ctx, errFactory)

				return ctx
			},
			orgID:               orgIDWithoutReachabilitySettings,
			expectErrorContains: "Reachability settings not enabled",
		},
		"--reachability should fail when reachability settings check fails": {
			ctx: func(ctx context.Context) context.Context {
				cfg := defaultConfig.Clone()
				cfg.Set(flags.FlagReachability, true)
				cfg.Set(constants.FeatureFlagReachabilityForCLI, true)

				ctx = cmdctx.WithConfig(ctx, cfg)
				ctx = cmdctx.WithLogger(ctx, &nopLogger)
				ctx = cmdctx.WithErrorFactory(ctx, errFactory)

				return ctx
			},
			orgID:               orgIDWithReachabilitySettingsErr,
			expectErrorContains: "failed to check reachability settings",
		},
	}
	for tcName, tc := range tcs {
		t.Run(tcName, func(t *testing.T) {
			t.Parallel()
			ctx := tc.ctx(t.Context())
			cfg := cmdctx.Config(ctx)
			flowCfg, err := ostest.ParseFlowConfig(cfg)
			require.NoError(t, err)

			flow, err := ostest.RouteToFlow(ctx, flowCfg, tc.orgID, sc)

			if tc.expectErrorContains == "" {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedFlow, flow)
			} else {
				assert.ErrorContains(t, err, tc.expectErrorContains)
			}
		})
	}
}

func Test_RouteToFlow_RiskScoreFlow(t *testing.T) {
	t.Parallel()
	defaultConfig := configuration.New()
	defaultConfig.Set(flags.FlagRiskScoreThreshold, -1)
	sc := setupSettingsClient(t)
	tcs := map[string]struct {
		ctx                 func(context.Context) context.Context
		expectedFlow        ostest.Flow
		expectErrorContains string
	}{
		"should route to depgraph flow when risk score FFs are enabled": {
			ctx: func(ctx context.Context) context.Context {
				cfg := defaultConfig.Clone()
				cfg.Set(constants.FeatureFlagRiskScore, true)
				cfg.Set(constants.FeatureFlagRiskScoreInCLI, true)

				ctx = cmdctx.WithConfig(ctx, cfg)
				ctx = cmdctx.WithLogger(ctx, &nopLogger)
				ctx = cmdctx.WithErrorFactory(ctx, errFactory)

				return ctx
			},
			expectedFlow: ostest.DepgraphFlow,
		},
		"should route to depgraph flow when --risk-score-threshold is set and risk score FFs are enabled": {
			ctx: func(ctx context.Context) context.Context {
				cfg := defaultConfig.Clone()
				cfg.Set(constants.FeatureFlagRiskScore, true)
				cfg.Set(constants.FeatureFlagRiskScoreInCLI, true)
				cfg.Set(flags.FlagRiskScoreThreshold, 100)

				ctx = cmdctx.WithConfig(ctx, cfg)
				ctx = cmdctx.WithLogger(ctx, &nopLogger)
				ctx = cmdctx.WithErrorFactory(ctx, errFactory)

				return ctx
			},
			expectedFlow: ostest.DepgraphFlow,
		},
		"should fail when --risk-score-threshold is set and risk score FF is missing": {
			ctx: func(ctx context.Context) context.Context {
				cfg := defaultConfig.Clone()
				cfg.Set(constants.FeatureFlagRiskScoreInCLI, true)
				cfg.Set(flags.FlagRiskScoreThreshold, 100)

				ctx = cmdctx.WithConfig(ctx, cfg)
				ctx = cmdctx.WithLogger(ctx, &nopLogger)
				ctx = cmdctx.WithErrorFactory(ctx, errFactory)

				return ctx
			},
			expectErrorContains: "The feature you are trying to use is not available for your organization.",
		},
		"should fail when --risk-score-threshold is set and risk score in the CLI FF is missing": {
			ctx: func(ctx context.Context) context.Context {
				cfg := defaultConfig.Clone()
				cfg.Set(constants.FeatureFlagRiskScore, true)
				cfg.Set(flags.FlagRiskScoreThreshold, 100)

				ctx = cmdctx.WithConfig(ctx, cfg)
				ctx = cmdctx.WithLogger(ctx, &nopLogger)
				ctx = cmdctx.WithErrorFactory(ctx, errFactory)

				return ctx
			},
			expectErrorContains: "The feature you are trying to use is not available for your organization.",
		},
	}
	for tcName, tc := range tcs {
		t.Run(tcName, func(t *testing.T) {
			t.Parallel()
			ctx := tc.ctx(t.Context())
			cfg := cmdctx.Config(ctx)
			flowCfg, err := ostest.ParseFlowConfig(cfg)
			require.NoError(t, err)

			flow, err := ostest.RouteToFlow(ctx, flowCfg, orgID, sc)

			if tc.expectErrorContains == "" {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedFlow, flow)
			} else {
				assert.ErrorContains(t, err, tc.expectErrorContains)
			}
		})
	}
}
