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

	"github.com/snyk/cli-extension-os-flows/internal/commands/ostest"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// Init registers the "test" workflow.
func Init(e workflow.Engine) error {
	if err := ostest.RegisterWorkflows(e); err != nil {
		return fmt.Errorf("error while registering open source test workflow: %w", err)
	}
	return nil
}
