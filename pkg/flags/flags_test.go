package flags_test

import (
	"testing"

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

func TestHTMLFlags(t *testing.T) {
	t.Run("html flag parses as bool", func(t *testing.T) {
		flagSet := flags.OSTestFlagSet()
		err := flagSet.Parse([]string{"--html"})
		require.NoError(t, err, "flag parsing should not fail")

		html, err := flagSet.GetBool(flags.FlagHTML)
		require.NoError(t, err, "getting flag value should not fail")
		assert.Equal(t, true, html)
	})

	t.Run("html-file-output flag parses as string", func(t *testing.T) {
		flagSet := flags.OSTestFlagSet()
		err := flagSet.Parse([]string{"--html-file-output=report.html"})
		require.NoError(t, err, "flag parsing should not fail")

		value, err := flagSet.GetString(flags.FlagHTMLFileOutput)
		require.NoError(t, err, "getting flag value should not fail")
		assert.Equal(t, "report.html", value)
	})

	t.Run("html flags are registered on OSTestFlagSet", func(t *testing.T) {
		flagSet := flags.OSTestFlagSet()

		for _, name := range []string{flags.FlagHTML, flags.FlagHTMLFileOutput} {
			assert.NotNil(t, flagSet.Lookup(name), "--%s should be registered on OSTestFlagSet", name)
		}
	})
}

func TestReportFlag(t *testing.T) {
	t.Run("report flag is registered on OSTestFlagSet as bool with default false", func(t *testing.T) {
		flagSet := flags.OSTestFlagSet()

		f := flagSet.Lookup(flags.FlagReport)
		require.NotNil(t, f, "--%s should be registered on OSTestFlagSet", flags.FlagReport)
		assert.Equal(t, "bool", f.Value.Type(), "--%s should be a bool flag", flags.FlagReport)
		assert.Equal(t, "false", f.DefValue, "--%s should default to false", flags.FlagReport)
		assert.NotEmpty(t, f.Usage, "--%s should have a non-empty usage string", flags.FlagReport)
	})

	t.Run("report flag is not registered on OSMonitorFlagSet", func(t *testing.T) {
		flagSet := flags.OSMonitorFlagSet()
		assert.Nil(t, flagSet.Lookup(flags.FlagReport), "--%s must not be on OSMonitorFlagSet", flags.FlagReport)
	})
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
