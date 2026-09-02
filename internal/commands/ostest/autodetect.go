package ostest

import (
	"context"
	"os"
	"strconv"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	"github.com/snyk/cli-extension-os-flows/internal/constants"
	"github.com/snyk/cli-extension-os-flows/pkg/unmanaged/detect"
)

// autoDetectEnabled reports whether SNYK_AUTODETECT_OSS is truthy. When on,
// os-flows inspects each input directory for C/C++ artefacts and, if any are
// found, runs an extra unmanaged scan via the legacy CLI alongside the managed
// scan. Off by default — flip to opt-in users without disturbing existing flows.
func autoDetectEnabled() bool {
	raw := os.Getenv(constants.AutodetectOSSEnvVar)
	if raw == "" {
		return false
	}
	v, _ := strconv.ParseBool(raw)
	return v
}

// detectCPPDirs returns the subset of dirs that contain C/C++ artefacts. The
// detector short-circuits on the first hit per directory, so the cost is
// bounded; see pkg/unmanaged/detect for the file-count / depth caps.
func detectCPPDirs(dirs []string) []string {
	var out []string
	for _, d := range dirs {
		if detect.HasCPPArtefacts(d) {
			out = append(out, d)
		}
	}
	return out
}

// invokeLegacyUnmanagedScan runs `legacycli` with --unmanaged injected into
// the raw arg list. The legacy CLI walks the input dirs itself, so we don't
// pass cppDirs explicitly — they're already in INPUT_DIRECTORY. We only invoke
// when at least one C/C++ dir was found, to avoid a no-op scan.
//
// LIMITATION: output merging is best-effort. The legacy CLI's workflow.Data
// carries a different content type than the native os-flows output, so the two
// streams render as separate sections rather than as a single unified report.
// A future native unmanaged.test workflow can replace this and produce one
// merged structured output.
func invokeLegacyUnmanagedScan(ctx context.Context) ([]workflow.Data, error) {
	ictx := cmdctx.Ictx(ctx)
	cfg := cmdctx.Config(ctx)

	legacyConfig := cfg.Clone()
	args := cfg.GetStringSlice(configuration.RAW_CMD_ARGS)
	if len(args) == 0 {
		args = os.Args[1:]
	}
	if !containsArg(args, "--unmanaged") {
		args = append(args, "--unmanaged")
	}
	legacyConfig.Set(configuration.RAW_CMD_ARGS, args)
	// Capture as workflow.Data instead of streaming to stdout, so it can be
	// returned alongside the managed scan's data.
	legacyConfig.Set(configuration.WORKFLOW_USE_STDIO, false)

	//nolint:wrapcheck // No need to wrap legacy errors.
	return ictx.GetEngine().InvokeWithConfig(workflow.NewWorkflowIdentifier("legacycli"), legacyConfig)
}

func containsArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}
