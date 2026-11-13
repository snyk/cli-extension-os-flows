package ostest

import (
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-os-flows/pkg/flags"
)

const failOnPatchable = "patchable"

// warnIfFailOnPatchable tells the user that --fail-on=patchable is deprecated. It warns
// on every flow, legacy included, because Snyk no longer publishes patches.
func warnIfFailOnPatchable(ictx workflow.InvocationContext) {
	if ictx.GetConfiguration().GetString(flags.FlagFailOn) != failOnPatchable {
		return
	}

	warning := snyk_errors.Error{
		Title:  "Deprecated flag value",
		Detail: "--fail-on=patchable is deprecated because Snyk no longer publishes patches. Use --fail-on=all instead.",
		Level:  "warn",
	}
	//nolint:errcheck // We don't need to fail the command due to UI errors.
	ictx.GetUserInterface().OutputError(warning)
}
