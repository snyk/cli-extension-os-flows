package routing_test

import (
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/cli-extension-os-flows/internal/commands/routing"
	"github.com/snyk/cli-extension-os-flows/pkg/flags"
)

func Test_RequiresLegacyByFlags_BoolFlags(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		flag        string
		wantTest    bool
		wantMonitor bool
	}{
		flags.FlagDocker:        {flag: flags.FlagDocker, wantTest: true, wantMonitor: true},
		flags.FlagContainer:     {flag: flags.FlagContainer, wantTest: true, wantMonitor: true},
		flags.FlagUnmanaged:     {flag: flags.FlagUnmanaged, wantTest: true, wantMonitor: true},
		flags.FlagPrintDeps:     {flag: flags.FlagPrintDeps, wantTest: true, wantMonitor: true},
		flags.FlagPrintDepPaths: {flag: flags.FlagPrintDepPaths, wantTest: true, wantMonitor: true},

		flags.FlagIAC:                 {flag: flags.FlagIAC, wantTest: true, wantMonitor: false},
		flags.FlagCode:                {flag: flags.FlagCode, wantTest: true, wantMonitor: false},
		flags.FlagPrintGraph:          {flag: flags.FlagPrintGraph, wantTest: true, wantMonitor: false},
		flags.FlagPrintEffectiveGraph: {flag: flags.FlagPrintEffectiveGraph, wantTest: true, wantMonitor: false},
	}

	for name, tc := range tests {
		t.Run("--"+name, func(t *testing.T) {
			t.Parallel()

			cfg := configuration.New()
			cfg.Set(tc.flag, true)

			assert.Equal(t, tc.wantTest, routing.RequiresLegacyByFlags(cfg, routing.CommandTest), "test routing for --%s", tc.flag)
			assert.Equal(t, tc.wantMonitor, routing.RequiresLegacyByFlags(cfg, routing.CommandMonitor), "monitor routing for --%s", tc.flag)
		})
	}
}

func Test_RequiresLegacyByFlags_FailOn(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		value       string
		wantTest    bool
		wantMonitor bool
	}{
		"patchable":  {value: "patchable", wantTest: true, wantMonitor: false},
		"upgradable": {value: "upgradable", wantTest: false, wantMonitor: false},
		"all":        {value: "all", wantTest: false, wantMonitor: false},
	}

	for name, tc := range tests {
		t.Run("--fail-on="+name, func(t *testing.T) {
			t.Parallel()

			cfg := configuration.New()
			cfg.Set(flags.FlagFailOn, tc.value)

			assert.Equal(t, tc.wantTest, routing.RequiresLegacyByFlags(cfg, routing.CommandTest))
			assert.Equal(t, tc.wantMonitor, routing.RequiresLegacyByFlags(cfg, routing.CommandMonitor))
		})
	}
}

func Test_RequiresLegacyByFlags_NoFlags(t *testing.T) {
	t.Parallel()

	cfg := configuration.New()

	assert.False(t, routing.RequiresLegacyByFlags(cfg, routing.CommandTest))
	assert.False(t, routing.RequiresLegacyByFlags(cfg, routing.CommandMonitor))
}
