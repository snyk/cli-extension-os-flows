package flags_test

import (
	"testing"

	"github.com/snyk/cli-extension-os-flows/pkg/flags"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
