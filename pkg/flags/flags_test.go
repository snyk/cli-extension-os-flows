package flags_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/legacy"
	depgraphlogger "github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
	"github.com/snyk/go-application-framework/pkg/configuration"
	gafmocks "github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/pkg/flags"
)

func TestReachabilityFlag(t *testing.T) {
	flagSets := []struct {
		name     string
		createFn func() *pflag.FlagSet
	}{
		{
			name:     "OSTestFlagSet",
			createFn: flags.OSTestFlagSet,
		},
		{
			name:     "OSMonitorFlagSet",
			createFn: flags.OSMonitorFlagSet,
		},
	}

	testCases := []struct {
		name     string
		args     []string
		expected bool
	}{
		{
			name:     "no flag provided - default false",
			args:     []string{},
			expected: false,
		},
		{
			name:     "flag without value - enables feature",
			args:     []string{"--reachability"},
			expected: true,
		},
		{
			name:     "flag with explicit true",
			args:     []string{"--reachability=true"},
			expected: true,
		},
		{
			name:     "flag with explicit false",
			args:     []string{"--reachability=false"},
			expected: false,
		},
	}

	for _, fs := range flagSets {
		t.Run(fs.name, func(t *testing.T) {
			for _, tt := range testCases {
				t.Run(tt.name, func(t *testing.T) {
					flagSet := fs.createFn()
					err := flagSet.Parse(tt.args)
					require.NoError(t, err, "flag parsing should not fail")

					reachability, err := flagSet.GetBool(flags.FlagReachability)
					require.NoError(t, err, "getting flag value should not fail")
					assert.Equal(t, tt.expected, reachability, "reachability flag value should match expected")
				})
			}
		})
	}
}

func TestNonOpenSourceTestTypeFlags(t *testing.T) {
	for _, name := range []string{flags.FlagIAC, flags.FlagDocker, flags.FlagContainer, flags.FlagCode} {
		t.Run(fmt.Sprintf("--%s parses as a bool on OSTestFlagSet", name), func(t *testing.T) {
			flagSet := flags.OSTestFlagSet()
			require.NotNil(t, flagSet.Lookup(name), "--%s should be registered on OSTestFlagSet", name)

			err := flagSet.Parse([]string{"--" + name})
			require.NoError(t, err, "flag parsing should not fail")

			value, err := flagSet.GetBool(name)
			require.NoError(t, err, "getting flag value should not fail")
			assert.True(t, value)
		})
	}
}

func TestOSMonitorFlagSet_ContainerFlags(t *testing.T) {
	for _, name := range []string{flags.FlagDocker, flags.FlagContainer} {
		t.Run(fmt.Sprintf("--%s parses as a bool on OSMonitorFlagSet", name), func(t *testing.T) {
			flagSet := flags.OSMonitorFlagSet()
			require.NotNil(t, flagSet.Lookup(name), "--%s should be registered on OSMonitorFlagSet", name)

			err := flagSet.Parse([]string{"alpine:3", "--" + name})
			require.NoError(t, err, "flag parsing should not fail")

			value, err := flagSet.GetBool(name)
			require.NoError(t, err, "getting flag value should not fail")
			assert.True(t, value)
			assert.Equal(t, []string{"alpine:3"}, flagSet.Args(), "the image must stay a positional argument")
		})
	}
}

func TestOSTestFlagSet_HasMonitorFlag(t *testing.T) {
	fs := flags.OSTestFlagSet()
	f := fs.Lookup(flags.FlagMonitor)
	require.NotNil(t, f, "expected --monitor to be registered on the OS test flag set")
	assert.Equal(t, "false", f.DefValue, "--monitor should default to false")
}

func TestRemoteRepoURLFlag(t *testing.T) {
	flagSets := []struct {
		name     string
		createFn func() *pflag.FlagSet
	}{
		{
			name:     "OSTestFlagSet",
			createFn: flags.OSTestFlagSet,
		},
		{
			name:     "OSMonitorFlagSet",
			createFn: flags.OSMonitorFlagSet,
		},
	}

	for _, fs := range flagSets {
		t.Run(fs.name, func(t *testing.T) {
			flagSet := fs.createFn()
			err := flagSet.Parse([]string{"--remote-repo-url=https://github.com/example/repo.git"})
			require.NoError(t, err, "flag parsing should not fail")

			value, err := flagSet.GetString(flags.FlagRemoteRepoURL)
			require.NoError(t, err, "getting flag value should not fail")
			assert.Equal(t, "https://github.com/example/repo.git", value)
		})
	}
}

func TestMavenPluginFlags_BindIntoConfig(t *testing.T) {
	flagSets := []struct {
		name     string
		createFn func() *pflag.FlagSet
	}{
		{
			name:     "OSTestFlagSet",
			createFn: flags.OSTestFlagSet,
		},
		{
			name:     "OSMonitorFlagSet",
			createFn: flags.OSMonitorFlagSet,
		},
	}

	flagNames := []string{flags.FlagMavenSkipWrapper, flags.FlagIncludeProvenance}

	testCases := []struct {
		name     string
		args     func(flagName string) []string
		expected bool
	}{
		{
			name:     "no flag provided - default false",
			args:     func(string) []string { return []string{} },
			expected: false,
		},
		{
			name:     "flag provided - enabled",
			args:     func(flagName string) []string { return []string{"--" + flagName} },
			expected: true,
		},
	}

	for _, fs := range flagSets {
		for _, flagName := range flagNames {
			t.Run(fs.name+"/"+flagName, func(t *testing.T) {
				for _, tt := range testCases {
					t.Run(tt.name, func(t *testing.T) {
						flagSet := fs.createFn()
						require.NotNil(t, flagSet.Lookup(flagName), "--%s should be registered on %s", flagName, fs.name)
						require.NoError(t, flagSet.Parse(tt.args(flagName)), "flag parsing should not fail")

						cfg := configuration.New()
						require.NoError(t, cfg.AddFlagSet(flagSet))

						assert.Equal(t, tt.expected, cfg.GetBool(flagName))
					})
				}
			})
		}
	}
}

// TestPythonSkipUnresolvedFlag_ReachesLegacyCLI pins OSF-641. Nothing in this
// extension reads --skip-unresolved: cli-extension-dep-graph's legacy plugin
// copies it from this flag set's values into the legacy CLI argv, and leaves
// out a value it cannot read without raising an error. The test runs that
// plugin, so it fails when the two extensions disagree on the flag's type.
func TestPythonSkipUnresolvedFlag_ReachesLegacyCLI(t *testing.T) {
	flagSets := []struct {
		name     string
		createFn func() *pflag.FlagSet
	}{
		{
			name:     "OSTestFlagSet",
			createFn: flags.OSTestFlagSet,
		},
	}

	testCases := []struct {
		name     string
		args     []string
		expected []string
	}{
		{
			name:     "no flag provided - not forwarded",
			args:     []string{},
			expected: nil,
		},
		{
			name:     "flag without value - forwarded as true",
			args:     []string{"--skip-unresolved"},
			expected: []string{"--skip-unresolved=true"},
		},
		{
			name:     "flag with explicit true",
			args:     []string{"--skip-unresolved=true"},
			expected: []string{"--skip-unresolved=true"},
		},
		{
			name:     "flag with explicit false",
			args:     []string{"--skip-unresolved=false"},
			expected: []string{"--skip-unresolved=false"},
		},
	}

	for _, fs := range flagSets {
		t.Run(fs.name, func(t *testing.T) {
			for _, tt := range testCases {
				t.Run(tt.name, func(t *testing.T) {
					var forwarded []string
					for _, arg := range legacyCLIArgs(t, fs.createFn(), tt.args) {
						if strings.HasPrefix(arg, "--"+flags.FlagPythonSkipUnresolved) {
							forwarded = append(forwarded, arg)
						}
					}
					assert.Equal(t, tt.expected, forwarded)
				})
			}
		})
	}
}

// legacyCLIArgs parses args with flagSet and returns the argv that
// cli-extension-dep-graph's legacy plugin builds for the legacy CLI from the
// resulting configuration. The legacy CLI itself is not run.
func legacyCLIArgs(t *testing.T, flagSet *pflag.FlagSet, args []string) []string {
	t.Helper()

	require.NoError(t, flagSet.Parse(args), "flag parsing should not fail")
	cfg := configuration.New()
	require.NoError(t, cfg.AddFlagSet(flagSet))

	ctrl := gomock.NewController(t)
	var legacyArgs []string
	engine := gafmocks.NewMockEngine(ctrl)
	engine.EXPECT().
		InvokeWithConfig(workflow.NewWorkflowIdentifier("legacycli"), gomock.Any()).
		DoAndReturn(func(_ workflow.Identifier, legacyCfg configuration.Configuration) ([]workflow.Data, error) {
			legacyArgs = legacyCfg.GetStringSlice(configuration.RAW_CMD_ARGS)
			return nil, nil
		})

	nopLogger := zerolog.Nop()
	ictx := gafmocks.NewMockInvocationContext(ctrl)
	ictx.EXPECT().GetConfiguration().Return(cfg).AnyTimes()
	ictx.EXPECT().GetEngine().Return(engine).AnyTimes()
	ictx.EXPECT().GetEnhancedLogger().Return(&nopLogger).AnyTimes()

	err := legacy.NewPlugin(ictx).BuildDepGraphsFromDir(
		t.Context(), depgraphlogger.Nop(), t.TempDir(), &ecosystems.SCAPluginOptions{},
		func(ecosystems.SCAResult) error { return nil },
	)
	require.NoError(t, err)

	return legacyArgs
}
