package ostest

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/workflow"

	service "github.com/snyk/cli-extension-os-flows/internal/common"
	"github.com/snyk/cli-extension-os-flows/internal/errors"
	"github.com/snyk/cli-extension-os-flows/internal/flags"
)

// RunUnifiedTestFlow handles the unified test API flow.
func RunUnifiedTestFlow(
	ctx context.Context,
	testClient testapi.TestClient,
	filename string,
	riskScoreThreshold *uint16,
	severityThreshold *testapi.Severity,
	ictx workflow.InvocationContext,
	orgID string,
	errFactory *errors.ErrorFactory,
	logger *zerolog.Logger,
) ([]workflow.Data, error) {
	logger.Info().Msg("Starting open source test")

	// Create depgraph
	depGraph, err := createDepGraph(ictx)
	if err != nil {
		return nil, fmt.Errorf("failed to create depgraph: %w", err)
	}

	// Create depgraph subject
	depGraphSubject := testapi.DepGraphSubjectCreate{
		Type:     testapi.DepGraphSubjectCreateTypeDepGraph,
		DepGraph: depGraph,
		Locator: testapi.LocalPathLocator{
			Paths: []string{filename},
			Type:  testapi.LocalPath,
		},
	}

	// Create test subject with depgraph
	var subject testapi.TestSubjectCreate
	err = subject.FromDepGraphSubjectCreate(depGraphSubject)
	if err != nil {
		return nil, fmt.Errorf("failed to create test subject: %w", err)
	}

	// Only create local policy if risk score or severity threshold are specified
	var localPolicy *testapi.LocalPolicy
	if riskScoreThreshold != nil || severityThreshold != nil {
		localPolicy = &testapi.LocalPolicy{}
		if riskScoreThreshold != nil {
			localPolicy.RiskScoreThreshold = riskScoreThreshold
		}
		if severityThreshold != nil {
			localPolicy.SeverityThreshold = severityThreshold
		}
	}

	// Project name assigned as follows: --project-name || config project name || scannedProject?.depTree?.name
	// TODO: use project name from Config file
	// TODO: verify - depTree is a legacy depgraph concept that I don't see in cli-extension-dep-graph, but the name
	// appears to come from the first Pkg item.
	config := ictx.GetConfiguration()
	projectName := config.GetString(flags.FlagProjectName)
	if projectName == "" && len(depGraph.Pkgs) > 0 {
		projectName = depGraph.Pkgs[0].Info.Name
	}

	packageManager := depGraph.PkgManager.Name
	depCount := max(0, len(depGraph.Pkgs)-1)

	// Run the test with the depgraph subject
	return RunTest(ctx, testClient, subject, projectName, packageManager, depCount, orgID, errFactory, logger, localPolicy)
}

// createDepGraph creates a depgraph from the file parameter in the context.
func createDepGraph(ictx workflow.InvocationContext) (testapi.IoSnykApiV1testdepgraphRequestDepGraph, error) {
	var contents []byte
	var err error

	depGraphResult, err := service.GetDepGraph(ictx)
	if err != nil {
		return testapi.IoSnykApiV1testdepgraphRequestDepGraph{}, fmt.Errorf("failed to get dependency graph: %w", err)
	}

	if len(depGraphResult.DepGraphBytes) > 1 {
		err = fmt.Errorf("multiple depgraphs found, but only one is currently supported")
		return testapi.IoSnykApiV1testdepgraphRequestDepGraph{}, err
	}
	// TODO revisit handling multiple depgraphs
	contents = depGraphResult.DepGraphBytes[0]

	var depGraphStruct testapi.IoSnykApiV1testdepgraphRequestDepGraph
	err = json.Unmarshal(contents, &depGraphStruct)
	if err != nil {
		return testapi.IoSnykApiV1testdepgraphRequestDepGraph{},
			fmt.Errorf("unmarshaling depGraph from args failed: %w", err)
	}

	return depGraphStruct, nil
}
