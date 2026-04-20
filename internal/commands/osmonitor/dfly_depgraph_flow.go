package osmonitor

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	"github.com/snyk/cli-extension-os-flows/internal/commands/ostest"
	"github.com/snyk/cli-extension-os-flows/internal/common"
	"github.com/snyk/cli-extension-os-flows/internal/util"
)

// RunDflyMonitorFlow runs the dragonfly depgraph flow for `snyk monitor`.
// It iterates over all input directories, resolves dep graphs, uploads them,
// runs a test with publish_report=true, and returns the aggregated workflow output.
func RunDflyMonitorFlow(
	ctx context.Context,
	inputDirs []string,
	orgUUID uuid.UUID,
	clients common.FlowClients,
) ([]workflow.Data, error) {
	cfg := cmdctx.Config(ctx)
	dgResolver := common.NewDepgraphResolver()
	var allWfData []workflow.Data

	for _, inputDir := range inputDirs {
		localPolicy, err := common.CreateLocalPolicy(ctx, inputDir)
		if err != nil {
			return nil, fmt.Errorf("failed to create local policy: %w", err)
		}

		reachOpts, err := common.ResolveMonitorReachabilityOpts(ctx, cfg, orgUUID, inputDir)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve reachability options: %w", err)
		}

		_, wfData, err := common.RunDflyDepgraphFlow(
			ctx, inputDir, dgResolver, clients, orgUUID, localPolicy, reachOpts, util.Ptr(true), ostest.RunTestWithResources,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to run depgraph flow: %w", err)
		}

		allWfData = append(allWfData, wfData...)
	}

	return handleDflyOutput(ctx, allWfData)
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
