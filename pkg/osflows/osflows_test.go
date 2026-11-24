package osflows_test

import (
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/commands/osmonitor"
	"github.com/snyk/cli-extension-os-flows/internal/commands/ostest"
	"github.com/snyk/cli-extension-os-flows/pkg/flags"
	"github.com/snyk/cli-extension-os-flows/pkg/osflows"
)

func TestInit_TestAndMonitorWorkflowsAcceptCommitIDFlag(t *testing.T) {
	engine := workflow.NewWorkFlowEngine(configuration.NewWithOpts())
	require.NoError(t, osflows.Init(engine))

	for _, id := range []workflow.Identifier{ostest.WorkflowID, osmonitor.WorkflowID} {
		t.Run(id.Host, func(t *testing.T) {
			entry, ok := engine.GetWorkflow(id)
			require.True(t, ok)
			flagSet := workflow.FlagsetFromConfigurationOptions(entry.GetConfigurationOptions())
			require.NotNil(t, flagSet.Lookup(flags.FlagCommitID), "--%s is not registered", flags.FlagCommitID)

			require.NoError(t, flagSet.Parse([]string{"--commit-id", "0123456789abcdef0123456789abcdef01234567", "path"}))

			value, err := flagSet.GetString(flags.FlagCommitID)
			require.NoError(t, err)
			assert.Equal(t, "0123456789abcdef0123456789abcdef01234567", value)
			assert.Equal(t, []string{"path"}, flagSet.Args())
		})
	}
}
