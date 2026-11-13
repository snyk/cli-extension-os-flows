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

var sharedLegacyOnlyFlags = []string{
	flags.FlagDocker,
	flags.FlagContainer,
	flags.FlagUnmanaged,
	flags.FlagPrintDeps,
	flags.FlagPrintDepPaths,
}

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

	if cmd == CommandTest {
		return anyFlagSet(cfg, testOnlyLegacyFlags)
	}

	return false
}

func anyFlagSet(cfg configuration.Configuration, names []string) bool {
	for _, name := range names {
		if cfg.GetBool(name) {
			return true
		}
	}

	return false
}
