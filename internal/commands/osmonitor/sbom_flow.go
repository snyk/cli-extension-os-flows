package osmonitor

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/google/uuid"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	"github.com/snyk/cli-extension-os-flows/internal/commands/ostest"
	"github.com/snyk/cli-extension-os-flows/internal/common"
	"github.com/snyk/cli-extension-os-flows/internal/util"
)

// RunSbomMonitorFlow uploads an SBOM document and runs a test with publish_report=true
// to persist it as a monitored project. It resolves local policy and reachability options
// internally, mirroring how RunDflyMonitorFlow handles setup per input directory.
func RunSbomMonitorFlow(
	ctx context.Context,
	clients common.FlowClients,
	sbomPath string,
	orgUUID uuid.UUID,
) ([]workflow.Data, error) {
	cfg := cmdctx.Config(ctx)
	targetDir := filepath.Dir(sbomPath)

	localPolicy, err := common.CreateLocalPolicy(ctx, targetDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create local policy: %w", err)
	}

	reachOpts, err := common.ResolveMonitorReachabilityOpts(ctx, cfg, orgUUID, targetDir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve reachability options: %w", err)
	}

	_, wfData, err := common.RunSbomFlow(
		ctx, sbomPath, clients, orgUUID, localPolicy, reachOpts,
		util.Ptr(true), ostest.RunTestWithResources,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to run sbom flow: %w", err)
	}

	return handleDflyOutput(ctx, wfData)
}
