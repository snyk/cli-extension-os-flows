package osmonitor

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	"github.com/snyk/cli-extension-os-flows/internal/commands/ostest"
	"github.com/snyk/cli-extension-os-flows/internal/common"
	"github.com/snyk/cli-extension-os-flows/internal/outputworkflow"
	"github.com/snyk/cli-extension-os-flows/pkg/flags"
)

// RunDflyMonitorFlow runs the dragonfly depgraph flow for `snyk monitor`.
// It iterates over all input directories, resolves dep graphs, uploads them,
// runs a test with monitor=true, and returns legacy monitor's per-project output.
// With JSON output it returns the test's workflow output instead.
func RunDflyMonitorFlow(
	ctx context.Context,
	inputDirs []string,
	orgUUID uuid.UUID,
	clients common.FlowClients,
	dgResolver common.DepgraphResolver,
) ([]workflow.Data, error) {
	cfg := cmdctx.Config(ctx)
	cfg.Set(flags.FlagMonitor, true)
	var allWfData []workflow.Data
	var projects []monitoredProject

	for _, inputDir := range inputDirs {
		localPolicy, err := common.CreateLocalPolicy(ctx, inputDir)
		if err != nil {
			var catalogErr snyk_errors.Error
			if errors.As(err, &catalogErr) {
				//nolint:wrapcheck // Wrapping would hide the user-facing policy error.
				return nil, err
			}
			return nil, fmt.Errorf("failed to create local policy: %w", err)
		}

		reachOpts, err := common.ResolveMonitorReachabilityOpts(ctx, cfg, orgUUID, inputDir)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve reachability options: %w", err)
		}

		recorder := &recordingDepgraphResolver{DepgraphResolver: dgResolver}
		_, wfData, err := common.RunDflyDepgraphFlow(
			ctx, inputDir, recorder, clients, orgUUID, localPolicy, reachOpts, ostest.RunTestWithResources,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to run depgraph flow: %w", err)
		}

		allWfData = append(allWfData, wfData...)
		projects = append(projects, monitoredProjects(inputDir, recorder.depGraphs, wfData)...)
	}

	if cfg.GetBool(outputworkflow.OutputConfigKeyJSON) || cfg.GetString(outputworkflow.OutputConfigKeyJSONFile) != "" {
		return handleDflyOutput(ctx, allWfData)
	}

	return []workflow.Data{monitorOutputData(ctx, projects)}, nil
}

func handleDflyOutput(ctx context.Context, outputData []workflow.Data) ([]workflow.Data, error) {
	ictx := cmdctx.Ictx(ctx)
	progressBar := cmdctx.ProgressBar(ctx)

	//nolint:errcheck // We don't need to fail the command due to UI errors.
	progressBar.Clear()

	//nolint:errcheck // Best-effort user notification.
	ictx.GetUserInterface().Output("Monitoring...\n")

	return outputData, nil
}
