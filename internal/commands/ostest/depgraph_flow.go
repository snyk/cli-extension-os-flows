package ostest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/workflow"

	service "github.com/snyk/cli-extension-os-flows/internal/common"
	"github.com/snyk/cli-extension-os-flows/internal/errors"
	"github.com/snyk/cli-extension-os-flows/internal/flags"
	"github.com/snyk/cli-extension-os-flows/internal/legacy/definitions"
)

// RunUnifiedTestFlow handles the unified test API flow.
func RunUnifiedTestFlow(
	ctx context.Context,
	ictx workflow.InvocationContext,
	testClient testapi.TestClient,
	riskScoreThreshold *uint16,
	severityThreshold *testapi.Severity,
	orgID string,
	errFactory *errors.ErrorFactory,
	logger *zerolog.Logger,
) ([]workflow.Data, error) {
	logger.Info().Msg("Starting open source test")

	// Create depgraphs and get their associated target files
	depGraphs, displayTargetFiles, err := createDepGraphs(ictx)
	if err != nil {
		return nil, err
	}
	var allFindings []definitions.LegacyVulnerabilityResponse
	var allSummaries []workflow.Data

	localPolicy := createLocalPolicy(riskScoreThreshold, severityThreshold)

	for i, depGraph := range depGraphs {
		displayTargetFile := ""
		if i < len(displayTargetFiles) {
			displayTargetFile = displayTargetFiles[i]
		}

		// Create depgraph subject
		depGraphSubject := testapi.DepGraphSubjectCreate{
			Type:     testapi.DepGraphSubjectCreateTypeDepGraph,
			DepGraph: depGraph,
			Locator: testapi.LocalPathLocator{
				Paths: []string{displayTargetFile},
				Type:  testapi.LocalPath,
			},
		}

		// Create test subject with depgraph
		var subject testapi.TestSubjectCreate
		err = subject.FromDepGraphSubjectCreate(depGraphSubject)
		if err != nil {
			return nil, fmt.Errorf("failed to create test subject: %w", err)
		}

		// Project name assigned as follows: --project-name || config project name || scannedProject?.depTree?.name
		// TODO: use project name from Config file
		config := ictx.GetConfiguration()
		projectName := config.GetString(flags.FlagProjectName)
		if projectName == "" && len(depGraph.Pkgs) > 0 {
			projectName = depGraph.Pkgs[0].Info.Name
		}

		packageManager := depGraph.PkgManager.Name
		depCount := max(0, len(depGraph.Pkgs)-1)

		// Run the test with the depgraph subject
		findings, summary, err := RunTest(ctx, testClient, subject, projectName, packageManager, depCount, displayTargetFile, orgID, errFactory, logger, localPolicy)
		if err != nil {
			return nil, err
		}

		if findings != nil {
			allFindings = append(allFindings, *findings)
		}
		if summary != nil {
			allSummaries = append(allSummaries, summary)
		}
	}

	var finalOutput []workflow.Data
	if len(allFindings) > 0 {
		var findingsData any
		if len(allFindings) == 1 {
			findingsData = allFindings[0]
		} else {
			findingsData = allFindings
		}

		var buffer bytes.Buffer
		encoder := json.NewEncoder(&buffer)
		encoder.SetEscapeHTML(false)
		encoder.SetIndent("", "  ")
		err := encoder.Encode(findingsData)
		if err != nil {
			return nil, errFactory.NewLegacyJSONTransformerError(fmt.Errorf("marshaling to json: %w", err))
		}
		// encoder.Encode adds a newline, which we trim to match Marshal's behavior.
		findingsBytes := bytes.TrimRight(buffer.Bytes(), "\n")

		finalOutput = append(finalOutput, NewWorkflowData(ApplicationJSONContentType, findingsBytes))
	}

	finalOutput = append(finalOutput, allSummaries...)

	return finalOutput, nil
}

// Create local policy only if risk score or severity threshold are specified.
func createLocalPolicy(riskScoreThreshold *uint16, severityThreshold *testapi.Severity) *testapi.LocalPolicy {
	if riskScoreThreshold == nil && severityThreshold == nil {
		return nil
	}

	localPolicy := &testapi.LocalPolicy{}
	if riskScoreThreshold != nil {
		localPolicy.RiskScoreThreshold = riskScoreThreshold
	}
	if severityThreshold != nil {
		localPolicy.SeverityThreshold = severityThreshold
	}
	return localPolicy
}

// createDepGraphs creates depgraphs from the file parameter in the context.
func createDepGraphs(ictx workflow.InvocationContext) ([]testapi.IoSnykApiV1testdepgraphRequestDepGraph, []string, error) {
	depGraphResult, err := service.GetDepGraph(ictx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get dependency graph: %w", err)
	}

	if len(depGraphResult.DepGraphBytes) == 0 {
		return nil, nil, fmt.Errorf("no dependency graphs found")
	}

	depGraphs := make([]testapi.IoSnykApiV1testdepgraphRequestDepGraph, len(depGraphResult.DepGraphBytes))
	for i, depGraphBytes := range depGraphResult.DepGraphBytes {
		var depGraphStruct testapi.IoSnykApiV1testdepgraphRequestDepGraph
		err = json.Unmarshal(depGraphBytes, &depGraphStruct)
		if err != nil {
			return nil, nil,
				fmt.Errorf("unmarshaling depGraph from args failed: %w", err)
		}
		depGraphs[i] = depGraphStruct
	}

	return depGraphs, depGraphResult.DisplayTargetFiles, nil
}
