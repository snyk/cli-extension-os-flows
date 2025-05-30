package ostest

import (
	"fmt"

	"github.com/snyk/cli-extension-os-flows/internal/errors"
	"github.com/snyk/cli-extension-os-flows/internal/flags"
	"github.com/snyk/go-application-framework/pkg/local_workflows/code_workflow"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

var WorkflowID = workflow.NewWorkflowIdentifier("test")

func RegisterWorkflows(e workflow.Engine) error {
	// Check if workflow already exists
	if existing, _ := e.GetWorkflow(WorkflowID); existing != nil {
		return fmt.Errorf("workflow with ID %s already exists", WorkflowID)
	}

	osTestFlagset := flags.GetOSTestFlagSet()

	c := workflow.ConfigurationOptionsFromFlagset(osTestFlagset)

	if _, err := e.Register(WorkflowID, c, OSWorkflow); err != nil {
		return fmt.Errorf("error while registering test workflow: %w", err)
	}

	return nil
}

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
		return code_workflow.EntryPointLegacy(icontext)
	}

	// TODO: Implement new workflow with risk score calculation
	logger.Println("OS Test workflow not yet implemented")
	logger.Println("Risk score threshold	= ", riskScoreThreshold)
	logger.Println("Force Unified Test API 	= ", config.GetBool(flags.FlagUnifiedTestAPI))

	return nil, errFactory.NewNotImplementedError()
}
