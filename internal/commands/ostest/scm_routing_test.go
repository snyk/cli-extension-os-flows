package ostest_test

import (
	"fmt"
	"testing"

	gogit "github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/orchestrator"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	"github.com/snyk/cli-extension-os-flows/internal/commands/ostest"
	"github.com/snyk/cli-extension-os-flows/internal/constants"
	"github.com/snyk/cli-extension-os-flows/internal/settings"
	"github.com/snyk/cli-extension-os-flows/pkg/flags"
)

// initGitRepo creates a git repository in a temp dir. An empty remoteURL leaves it without a remote.
func initGitRepo(t *testing.T, remoteURL string) string {
	t.Helper()
	dir := t.TempDir()

	repo, err := gogit.PlainInit(dir, false)
	require.NoError(t, err)

	if remoteURL != "" {
		_, err = repo.CreateRemote(&gitconfig.RemoteConfig{Name: "origin", URLs: []string{remoteURL}})
		require.NoError(t, err)
	}

	return dir
}

// stdioMatcher matches a legacycli invocation by WORKFLOW_USE_STDIO, which only the legacy flow sets.
// The dfly flow's dependency resolution also invokes legacycli, but without it.
type stdioMatcher bool

func (m stdioMatcher) Matches(x any) bool {
	cfg, ok := x.(configuration.Configuration)
	return ok && cfg.GetBool(configuration.WORKFLOW_USE_STDIO) == bool(m)
}

func (m stdioMatcher) String() string {
	return fmt.Sprintf("has %s=%t", configuration.WORKFLOW_USE_STDIO, bool(m))
}

func TestOSWorkflow_DflyFF_NoGitRemote_UsesLegacy(t *testing.T) {
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

			mockEngine := mocks.NewMockEngine(ctrl)
			mockInvocationCtx := createMockInvocationCtxWithURL(t, ctrl, mockEngine, "")
			cfg := mockInvocationCtx.GetConfiguration()
			cfg.Set(constants.FeatureFlagDlfyCLIRollout, true)
			cfg.Set(configuration.INPUT_DIRECTORY, inputDirs(t))
			cfg.Set(configuration.RAW_CMD_ARGS, []string{"test"})

			mockEngine.EXPECT().
				InvokeWithConfig(legacyWorkflowID, stdioMatcher(true)).
				Return([]workflow.Data{}, nil).
				Times(1)

			_, err := ostest.OSWorkflow(mockInvocationCtx, []workflow.Data{})

			assert.NoError(t, err)
		})
	}
}

func TestOSWorkflow_DflyFF_WithScmContext_UsesDflyFlow(t *testing.T) {
	tests := map[string]func(t *testing.T, cfg configuration.Configuration){
		"git repository with a remote": func(t *testing.T, cfg configuration.Configuration) {
			t.Helper()
			cfg.Set(configuration.INPUT_DIRECTORY, []string{initGitRepo(t, "https://github.com/acme/repo.git")})
		},
		"--remote-repo-url without a git repository": func(t *testing.T, cfg configuration.Configuration) {
			t.Helper()
			cfg.Set(configuration.INPUT_DIRECTORY, []string{t.TempDir()})
			cfg.Set(flags.FlagRemoteRepoURL, "https://github.com/acme/repo.git")
		},
	}

	for name, setup := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockEngine := mocks.NewMockEngine(ctrl)
			mockInvocationCtx := createMockInvocationCtxWithURL(t, ctrl, mockEngine, "")
			cfg := mockInvocationCtx.GetConfiguration()
			cfg.Set(constants.FeatureFlagDlfyCLIRollout, true)
			setup(t, cfg)
			cfg.Set(configuration.RAW_CMD_ARGS, []string{"test"})

			// The dfly flow resolves dependencies through legacycli; the input dirs hold no
			// manifests, so it finds none. The legacy flow itself must not run.
			mockEngine.EXPECT().
				InvokeWithConfig(legacyWorkflowID, stdioMatcher(false)).
				Return([]workflow.Data{}, nil).
				AnyTimes()

			_, err := ostest.OSWorkflow(mockInvocationCtx, []workflow.Data{})

			require.ErrorContains(t, err, "No supported files found")
		})
	}
}

// Test_Routing_ScmContext covers ShouldUseLegacyFlow and RouteToFlow together: without SCM
// context the dfly rollout does not apply, so the run routes as it would with the rollout off.
func Test_Routing_ScmContext(t *testing.T) {
	t.Parallel()

	const remoteURL = "https://github.com/acme/repo.git"
	// Own org, settings client and logger rather than the package-level ones: using those here
	// makes govet's shadow check flag the locals that shadow them in other test files.
	scmOrgID := uuid.New()
	sc := settings.NewFakeClient(map[settings.OrgID]struct {
		IsEnabled bool
		Err       error
	}{scmOrgID: {IsEnabled: true}})
	scmLogger := zerolog.Nop()

	tcs := map[string]struct {
		setup             func(t *testing.T, cfg configuration.Configuration) []string
		missingScmContext bool
		expectedFlow      ostest.Flow
	}{
		"dfly rollout without a git remote uses legacy": {
			setup: func(t *testing.T, cfg configuration.Configuration) []string {
				t.Helper()
				cfg.Set(constants.FeatureFlagDlfyCLIRollout, true)
				return []string{initGitRepo(t, "")}
			},
			missingScmContext: true,
			expectedFlow:      ostest.LegacyFlow,
		},
		"dfly rollout with a git remote uses the dfly flow": {
			setup: func(t *testing.T, cfg configuration.Configuration) []string {
				t.Helper()
				cfg.Set(constants.FeatureFlagDlfyCLIRollout, true)
				return []string{initGitRepo(t, remoteURL)}
			},
			expectedFlow: ostest.DflyDepgraphFlow,
		},
		"dfly rollout with --remote-repo-url uses the dfly flow": {
			setup: func(t *testing.T, cfg configuration.Configuration) []string {
				t.Helper()
				cfg.Set(constants.FeatureFlagDlfyCLIRollout, true)
				cfg.Set(flags.FlagRemoteRepoURL, remoteURL)
				return []string{t.TempDir()}
			},
			expectedFlow: ostest.DflyDepgraphFlow,
		},
		"dfly rollout without a git remote and --sbom uses the sbom flow": {
			setup: func(t *testing.T, cfg configuration.Configuration) []string {
				t.Helper()
				cfg.Set(constants.FeatureFlagDlfyCLIRollout, true)
				cfg.Set(flags.FlagSBOM, "sbom.json")
				return []string{t.TempDir()}
			},
			missingScmContext: true,
			expectedFlow:      ostest.SbomFlow,
		},
		"dfly rollout without a git remote and --reachability uses the depgraph flow": {
			setup: func(t *testing.T, cfg configuration.Configuration) []string {
				t.Helper()
				cfg.Set(constants.FeatureFlagDlfyCLIRollout, true)
				cfg.Set(constants.FeatureFlagReachabilityForCLI, true)
				cfg.Set(flags.FlagReachability, true)
				return []string{t.TempDir()}
			},
			missingScmContext: true,
			expectedFlow:      ostest.DepgraphFlow,
		},
		"dfly rollout without a git remote and --risk-score-threshold uses the depgraph flow": {
			setup: func(t *testing.T, cfg configuration.Configuration) []string {
				t.Helper()
				cfg.Set(constants.FeatureFlagDlfyCLIRollout, true)
				cfg.Set(constants.FeatureFlagRiskScore, true)
				cfg.Set(constants.FeatureFlagRiskScoreInCLI, true)
				cfg.Set(flags.FlagRiskScoreThreshold, 700)
				return []string{t.TempDir()}
			},
			missingScmContext: true,
			expectedFlow:      ostest.DepgraphFlow,
		},
		"dfly rollout without a git remote and the unified test API rollout uses the depgraph flow": {
			setup: func(t *testing.T, cfg configuration.Configuration) []string {
				t.Helper()
				cfg.Set(constants.FeatureFlagDlfyCLIRollout, true)
				cfg.Set(orchestrator.FlagUnifiedTestAPIOsCLI.Key, true)
				return []string{t.TempDir()}
			},
			missingScmContext: true,
			expectedFlow:      ostest.DepgraphFlow,
		},
		"without the dfly rollout a missing git remote does not matter": {
			setup: func(t *testing.T, cfg configuration.Configuration) []string {
				t.Helper()
				cfg.Set(orchestrator.FlagUnifiedTestAPIOsCLI.Key, true)
				return []string{t.TempDir()}
			},
			missingScmContext: true,
			expectedFlow:      ostest.DepgraphFlow,
		},
	}

	for tcName, tc := range tcs {
		t.Run(tcName, func(t *testing.T) {
			t.Parallel()

			cfg := configuration.New()
			cfg.Set(flags.FlagRiskScoreThreshold, -1)
			inputDirs := tc.setup(t, cfg)

			ctx := t.Context()
			ctx = cmdctx.WithConfig(ctx, cfg)
			ctx = cmdctx.WithLogger(ctx, &scmLogger)
			ctx = cmdctx.WithErrorFactory(ctx, errFactory)

			flowCfg, err := ostest.ParseFlowConfig(cfg)
			require.NoError(t, err)

			flow := ostest.LegacyFlow
			useLegacy, err := ostest.ShouldUseLegacyFlow(ctx, flowCfg, inputDirs)
			require.NoError(t, err)
			if !useLegacy {
				flow, err = ostest.RouteToFlow(ctx, flowCfg, scmOrgID, sc)
				require.NoError(t, err)
			}

			assert.Equal(t, tc.missingScmContext, flowCfg.MissingScmContext)
			assert.Equal(t, tc.expectedFlow, flow)
		})
	}
}
