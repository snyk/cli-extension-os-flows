package osflows

import (
	"fmt"

	"github.com/snyk/cli-extension-os-flows/internal/commands/ostest"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func Init(e workflow.Engine) error {
	// register "test" workflow
	if err := ostest.RegisterWorkflows(e); err != nil {
		return fmt.Errorf("error while registering open source test workflow: %w", err)
	}

	return nil
}
