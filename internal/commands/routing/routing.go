// Package routing holds the flag-based routing rules that `snyk test` and
// `snyk monitor` share: which invocations the new flows cannot serve and have to
// hand back to the legacy CLI. The two commands expose almost the same flag
// surface, so keeping the decision here stops the two routers from drifting
// apart; the rules that genuinely differ are selected by Command.
package routing

import (
	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/cli-extension-os-flows/pkg/flags"
)

// Command identifies the command whose flags are being routed.
type Command string

const (
	// CommandTest selects the routing rules for `snyk test`.
	CommandTest Command = "test"
	// CommandMonitor selects the routing rules for `snyk monitor`.
	CommandMonitor Command = "monitor"
)

// failOnPatchable is the only --fail-on value the new flows cannot honor.
const failOnPatchable = "patchable"

// sharedLegacyOnlyFlags are the flags that neither command can serve from the new
// flows. --docker/--container select a container scan and --unmanaged a C/C++
// scan, which the new flows do not implement at all; --print-deps and
// --print-dep-paths print dependency output that only the legacy flow's
// ecosystem plugins produce.
var sharedLegacyOnlyFlags = []string{
	flags.FlagDocker,
	flags.FlagContainer,
	flags.FlagUnmanaged,
	flags.FlagPrintDeps,
	flags.FlagPrintDepPaths,
}

// testOnlyLegacyFlags are legacy-only for `test` but not for `monitor`. Legacy
// `monitor` ignores --iac and --code, and prints no dependency graph of its own
// (it reads --print-graph only as a Maven verbosity hint), so none of these
// are registered on the monitor flag set.
var testOnlyLegacyFlags = []string{
	flags.FlagIAC,
	flags.FlagCode,
	flags.FlagPrintGraph,
	flags.FlagPrintEffectiveGraph,
}

// RequiresLegacyByFlags reports whether cmd was invoked with a flag that only the
// legacy flow supports.
func RequiresLegacyByFlags(cfg configuration.Configuration, cmd Command) bool {
	if anyFlagSet(cfg, sharedLegacyOnlyFlags) {
		return true
	}

	if cmd != CommandTest {
		return false
	}

	// The unified test API has no notion of patches, so only legacy can honor this
	// --fail-on value. `monitor` has no --fail-on.
	return anyFlagSet(cfg, testOnlyLegacyFlags) || cfg.GetString(flags.FlagFailOn) == failOnPatchable
}

// anyFlagSet reports whether any of the named boolean flags is set.
func anyFlagSet(cfg configuration.Configuration, names []string) bool {
	for _, name := range names {
		if cfg.GetBool(name) {
			return true
		}
	}

	return false
}
