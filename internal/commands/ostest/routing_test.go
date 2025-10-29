package ostest_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	"github.com/snyk/cli-extension-os-flows/internal/commands/ostest"
	"github.com/snyk/cli-extension-os-flows/internal/constants"
	"github.com/snyk/cli-extension-os-flows/internal/flags"
	"github.com/snyk/cli-extension-os-flows/internal/settings"
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

		flowCfg := ostest.ParseFlowConfig(cfg)
		useLegacy, err := ostest.ShouldUseLegacyFlow(ctx, flowCfg)
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

				flowCfg := ostest.ParseFlowConfig(testCfg)
				_, err := ostest.ShouldUseLegacyFlow(ctx, flowCfg)

				assert.ErrorContains(t, err, "Invalid flag option")
			})
		}
	})

	t.Run("when legacy options are set", func(t *testing.T) {
		t.Parallel()
		legacyOptions := []string{flags.FlagPrintGraph, flags.FlagPrintDeps, flags.FlagPrintDepPaths, flags.FlagUnmanaged}
		for _, legacyOption := range legacyOptions {
			cfg := defaultConfig.Clone()
			cfg.Set(legacyOption, true)

			t.Run(fmt.Sprintf("--% should route to legacy command", legacyOption), func(t *testing.T) {
				t.Parallel()
				testCfg := cfg.Clone()
				ctx := t.Context()
				ctx = cmdctx.WithConfig(ctx, testCfg)
				ctx = cmdctx.WithLogger(ctx, &nopLogger)
				ctx = cmdctx.WithErrorFactory(ctx, errFactory)

				flowCfg := ostest.ParseFlowConfig(testCfg)
				useLegacy, err := ostest.ShouldUseLegacyFlow(ctx, flowCfg)
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

					flowCfg := ostest.ParseFlowConfig(testCfg)
					_, err := ostest.ShouldUseLegacyFlow(ctx, flowCfg)

					assert.ErrorContains(t, err, "Invalid flag option")
				})
			}
		}
	})

	t.Run("when no new options are provided", func(t *testing.T) {
		t.Parallel()
		cfg := defaultConfig.Clone()

		ctx := t.Context()
		ctx = cmdctx.WithConfig(ctx, cfg)
		ctx = cmdctx.WithLogger(ctx, &nopLogger)
		ctx = cmdctx.WithErrorFactory(ctx, errFactory)

		flowCfg := ostest.ParseFlowConfig(cfg)
		useLegacy, err := ostest.ShouldUseLegacyFlow(ctx, flowCfg)
		require.NoError(t, err)

		assert.True(t, useLegacy)
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
				cfg.Set(ostest.FeatureFlagSBOMTestReachability, true)

				ctx = cmdctx.WithConfig(ctx, cfg)
				ctx = cmdctx.WithLogger(ctx, &nopLogger)
				ctx = cmdctx.WithErrorFactory(ctx, errFactory)

				return ctx
			},
			orgID:        orgID,
			expectedFlow: ostest.SBOMReachabilityFlow,
		},
		"--reachability with --sbom and --reachability-filter should route to SBOM reachability flow when FF and reachability settings are enabled": {
			ctx: func(ctx context.Context) context.Context {
				cfg := defaultConfig.Clone()
				cfg.Set(flags.FlagSBOM, "sbom.json")
				cfg.Set(flags.FlagReachability, true)
				cfg.Set(flags.FlagReachabilityFilter, "reachable")
				cfg.Set(ostest.FeatureFlagSBOMTestReachability, true)

				ctx = cmdctx.WithConfig(ctx, cfg)
				ctx = cmdctx.WithLogger(ctx, &nopLogger)
				ctx = cmdctx.WithErrorFactory(ctx, errFactory)

				return ctx
			},
			orgID:        orgID,
			expectedFlow: ostest.SBOMReachabilityFlow,
		},
		"--reachability with --sbom should fail when FF is missing": {
			ctx: func(ctx context.Context) context.Context {
				cfg := defaultConfig.Clone()
				cfg.Set(flags.FlagSBOM, "sbom.json")
				cfg.Set(flags.FlagReachability, true)

				ctx = cmdctx.WithConfig(ctx, cfg)
				ctx = cmdctx.WithLogger(ctx, &nopLogger)
				ctx = cmdctx.WithErrorFactory(ctx, errFactory)

				return ctx
			},
			orgID:               orgID,
			expectErrorContains: "The feature you are trying to use is not available for your organization.",
		},
		"--reachability with --sbom should fail when reachability settings are disabled": {
			ctx: func(ctx context.Context) context.Context {
				cfg := defaultConfig.Clone()
				cfg.Set(flags.FlagSBOM, "sbom.json")
				cfg.Set(flags.FlagReachability, true)
				cfg.Set(ostest.FeatureFlagSBOMTestReachability, true)

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
				cfg.Set(ostest.FeatureFlagSBOMTestReachability, true)

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
			flowCfg := ostest.ParseFlowConfig(cfg)

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
				cfg.Set(ostest.FeatureFlagReachabilityForCLI, true)

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
				cfg.Set(ostest.FeatureFlagReachabilityForCLI, true)

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
			expectErrorContains: "The feature you are trying to use is not available for your organization.",
		},
		"--reachability should fail when reachability settings are disabled": {
			ctx: func(ctx context.Context) context.Context {
				cfg := defaultConfig.Clone()
				cfg.Set(flags.FlagReachability, true)
				cfg.Set(ostest.FeatureFlagReachabilityForCLI, true)

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
				cfg.Set(ostest.FeatureFlagReachabilityForCLI, true)

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
			flowCfg := ostest.ParseFlowConfig(cfg)

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
				cfg.Set(ostest.FeatureFlagRiskScore, true)
				cfg.Set(ostest.FeatureFlagRiskScoreInCLI, true)

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
				cfg.Set(ostest.FeatureFlagRiskScore, true)
				cfg.Set(ostest.FeatureFlagRiskScoreInCLI, true)
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
				cfg.Set(ostest.FeatureFlagRiskScoreInCLI, true)
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
				cfg.Set(ostest.FeatureFlagRiskScore, true)
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
			flowCfg := ostest.ParseFlowConfig(cfg)

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
