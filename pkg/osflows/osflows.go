// Package osflows provides Open Source test workflow functionality for the Snyk CLI extension.
//
// This package serves as the main entry point for initializing and registering
// Open Source test workflows with the Snyk CLI. It provides the necessary
// integration points between the Snyk CLI framework and the Open Source
// specific test workflows.
//
// The package is designed to be used by the Snyk CLI extension system and is
// responsible for setting up the required workflows and their configurations.
package osflows

import (
	"fmt"

	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-os-flows/internal/commands/osmonitor"
	"github.com/snyk/cli-extension-os-flows/internal/commands/ostest"
	"github.com/snyk/cli-extension-os-flows/internal/outputworkflow"
)

// LegacyCLIContentType is the  content type set on a WorkflowData
// to indicate that the results are coming from the legacy CLI.
const LegacyCLIContentType = ostest.LegacyCLIContentType

// Init registers the "test" workflow.
func Init(e workflow.Engine) error {
	if err := ostest.RegisterWorkflows(e); err != nil {
		return fmt.Errorf("error while registering open source test workflow: %w", err)
	}

	if err := osmonitor.RegisterWorkflows(e); err != nil {
		return fmt.Errorf("error while registering open source monitor workflow: %w", err)
	}

	if err := outputworkflow.InitOutputWorkflow(e); err != nil {
		return fmt.Errorf("error while registering open source output workflow: %w", err)
	}

	return nil
}
