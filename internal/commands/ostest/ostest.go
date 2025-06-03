// Package ostest implements the "test" command for the Snyk CLI's Open Source security testing.
//
// This package provides the core functionality for running Open Source security tests
// through the Snyk CLI. It handles workflow registration, command-line flag parsing,
// and implements the test execution logic with support for both legacy and new unified test flows.
//
// The package is primarily used by the main osflows package to register and expose
// the test command to the Snyk CLI framework.
package ostest

import (
	"fmt"

	"github.com/snyk/cli-extension-os-flows/internal/errors"
	"github.com/snyk/cli-extension-os-flows/internal/flags"
	"github.com/snyk/go-application-framework/pkg/local_workflows/code_workflow"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// WorkflowID is the identifier for the Open Source Test workflow.
var WorkflowID = workflow.NewWorkflowIdentifier("test")

// RegisterWorkflows registers the "test" workflow.
func RegisterWorkflows(e workflow.Engine) error {
	// Check if workflow already exists
	if existing, _ := e.GetWorkflow(WorkflowID); existing != nil {
		return fmt.Errorf("workflow with ID %s already exists", WorkflowID)
	}

	osTestFlagset := flags.OSTestFlagSet()

	c := workflow.ConfigurationOptionsFromFlagset(osTestFlagset)

	if _, err := e.Register(WorkflowID, c, OSWorkflow); err != nil {
		return fmt.Errorf("error while registering test workflow: %w", err)
	}

	return nil
}

// OSWorkflow is the entry point for the Open Source Test workflow.
func OSWorkflow(
	icontext workflow.InvocationContext,
	_ []workflow.Data,
) ([]workflow.Data, error) {
	logger := icontext.GetEnhancedLogger()
	errFactory := errors.NewErrorFactory(logger)

	logger.Println("OS Test workflow start")

	config := icontext.GetConfiguration()
	riskScoreThreshold := config.GetInt(flags.FlagRiskScoreThreshold)

	if !config.GetBool(flags.FlagUnifiedTestAPI) && riskScoreThreshold == -1 {
		logger.Debug().Msg("Using legacy flow since risk score threshold and unified test flags are disabled")
		data, err := code_workflow.EntryPointLegacy(icontext)
		if err != nil {
			return nil, fmt.Errorf("failed to run legacy code workflow: %w", err)
		}
		return data, nil
	}

	// TODO: Implement new workflow with risk score calculation
	logger.Println("OS Test workflow not yet implemented")
	logger.Println("Risk score threshold	= ", riskScoreThreshold)
	logger.Println("Force Unified Test API 	= ", config.GetBool(flags.FlagUnifiedTestAPI))

	return nil, errFactory.NewNotImplementedError()
}
