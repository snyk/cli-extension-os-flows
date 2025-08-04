package ostest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/local_workflows/content_type"
	"github.com/snyk/go-application-framework/pkg/workflow"

	service "github.com/snyk/cli-extension-os-flows/internal/common"
	"github.com/snyk/cli-extension-os-flows/internal/errors"
	"github.com/snyk/cli-extension-os-flows/internal/flags"
	"github.com/snyk/cli-extension-os-flows/internal/legacy/definitions"
	"github.com/snyk/cli-extension-os-flows/internal/outputworkflow"
)

// RunUnifiedTestFlow handles the unified test API flow.
func RunUnifiedTestFlow(
	ctx context.Context,
	ictx workflow.InvocationContext,
	testClient testapi.TestClient,
	orgID string,
	errFactory *errors.ErrorFactory,
	logger *zerolog.Logger,
	localPolicy *testapi.LocalPolicy,
) ([]workflow.Data, error) {
	logger.Info().Msg("Starting open source test")

	// Create depgraphs and get their associated target files
	depGraphs, displayTargetFiles, err := createDepGraphs(ictx)
	if err != nil {
		return nil, err
	}

	allLegacyFindings, allOutputData, err := testAllDepGraphs(
		ctx,
		ictx,
		testClient,
		orgID,
		errFactory,
		logger,
		localPolicy,
		depGraphs,
		displayTargetFiles,
	)
	if err != nil {
		return nil, err
	}

	//nolint:contextcheck // The handleOutput call chain is not context-aware
	return handleOutput(ictx, allLegacyFindings, allOutputData, errFactory)
}

func testAllDepGraphs(
	ctx context.Context,
	ictx workflow.InvocationContext,
	testClient testapi.TestClient,
	orgID string,
	errFactory *errors.ErrorFactory,
	logger *zerolog.Logger,
	localPolicy *testapi.LocalPolicy,
	depGraphs []*testapi.IoSnykApiV1testdepgraphRequestDepGraph,
	displayTargetFiles []string,
) ([]definitions.LegacyVulnerabilityResponse, []workflow.Data, error) {
	var allLegacyFindings []definitions.LegacyVulnerabilityResponse
	var allOutputData []workflow.Data

	for i, depGraph := range depGraphs {
		displayTargetFile := ""
		if i < len(displayTargetFiles) {
			displayTargetFile = displayTargetFiles[i]
		}

		subject, err := createTestSubject(depGraph, displayTargetFile)
		if err != nil {
			return nil, nil, err
		}

		projectName := getProjectName(ictx, depGraph)
		packageManager := depGraph.PkgManager.Name
		depCount := max(0, len(depGraph.Pkgs)-1)

		// Run the test with the depgraph subject
		legacyFinding, outputData, err := RunTest(
			ctx, ictx, testClient, subject, projectName, packageManager, depCount,
			displayTargetFile, orgID, errFactory, logger, localPolicy)
		if err != nil {
			return nil, nil, err
		}

		if legacyFinding != nil {
			allLegacyFindings = append(allLegacyFindings, *legacyFinding)
		}
		allOutputData = append(allOutputData, outputData...)
	}

	return allLegacyFindings, allOutputData, nil
}

func createTestSubject(
	depGraph *testapi.IoSnykApiV1testdepgraphRequestDepGraph,
	displayTargetFile string,
) (testapi.TestSubjectCreate, error) {
	// Create depgraph subject
	depGraphSubject := testapi.DepGraphSubjectCreate{
		Type:     testapi.DepGraphSubjectCreateTypeDepGraph,
		DepGraph: *depGraph,
		Locator: testapi.LocalPathLocator{
			Paths: []string{displayTargetFile},
			Type:  testapi.LocalPath,
		},
	}

	// Create test subject with depgraph
	var subject testapi.TestSubjectCreate
	err := subject.FromDepGraphSubjectCreate(depGraphSubject)
	if err != nil {
		return subject, fmt.Errorf("failed to create test subject: %w", err)
	}
	return subject, nil
}

func getProjectName(
	ictx workflow.InvocationContext,
	depGraph *testapi.IoSnykApiV1testdepgraphRequestDepGraph,
) string {
	// Project name assigned as follows: --project-name || config project name || scannedProject?.depTree?.name
	// TODO: use project name from Config file
	config := ictx.GetConfiguration()
	projectName := config.GetString(flags.FlagProjectName)
	if projectName == "" && len(depGraph.Pkgs) > 0 {
		projectName = depGraph.Pkgs[0].Info.Name
	}
	return projectName
}

func handleOutput(
	ictx workflow.InvocationContext,
	allLegacyFindings []definitions.LegacyVulnerabilityResponse,
	allOutputData []workflow.Data,
	errFactory *errors.ErrorFactory,
) ([]workflow.Data, error) {
	config := ictx.GetConfiguration()
	jsonOutput := config.GetBool(outputworkflow.OutputConfigKeyJSON)
	jsonFileOutput := config.GetString(outputworkflow.OutputConfigKeyJSONFile)

	// Human-readable output is suppressed only when --json is specified.
	wantsHumanReadable := !jsonOutput
	wantsJSONFile := jsonFileOutput != ""
	wantsJSONStdOut := jsonOutput

	var finalOutput []workflow.Data
	if wantsHumanReadable {
		outputDestination := outputworkflow.NewOutputDestination()
		// The output workflow returns data it did not handle, like test summaries for exit code calculation.
		remainingData, err := outputworkflow.EntryPoint(ictx, allOutputData, outputDestination)
		if err != nil {
			return nil, fmt.Errorf("failed to process output workflow: %w", err)
		}
		finalOutput = append(finalOutput, remainingData...)
	}

	// Handle JSON output to a file or stdout.
	if !wantsJSONFile && !wantsJSONStdOut || len(allLegacyFindings) == 0 {
		return finalOutput, nil
	}

	jsonBytes, err := prepareJSONOutput(allLegacyFindings, errFactory)
	if err != nil {
		return nil, err
	}

	if wantsJSONFile {
		if err := os.WriteFile(jsonFileOutput, jsonBytes, 0o600); err != nil {
			return nil, fmt.Errorf("failed to write JSON output to file: %w", err)
		}
	}

	if wantsJSONStdOut {
		finalOutput = append(finalOutput, NewWorkflowData(ApplicationJSONContentType, jsonBytes))
	}

	// If only JSON output to stdout was requested, we still need the summary for the exit code.
	if wantsJSONStdOut && !wantsHumanReadable {
		for _, d := range allOutputData {
			if strings.HasPrefix(d.GetContentType(), content_type.TEST_SUMMARY) {
				finalOutput = append(finalOutput, d)
			}
		}
	}

	return finalOutput, nil
}

func prepareJSONOutput(
	allLegacyFindings []definitions.LegacyVulnerabilityResponse,
	errFactory *errors.ErrorFactory,
) ([]byte, error) {
	if len(allLegacyFindings) == 0 {
		return nil, nil
	}

	var findingsData any
	if len(allLegacyFindings) == 1 {
		findingsData = allLegacyFindings[0]
	} else {
		findingsData = allLegacyFindings
	}

	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(findingsData); err != nil {
		return nil, errFactory.NewLegacyJSONTransformerError(fmt.Errorf("marshaling to json: %w", err))
	}
	// encoder.Encode adds a newline, which we trim to match Marshal's behavior.
	return bytes.TrimRight(buffer.Bytes(), "\n"), nil
}

// createDepGraphs creates depgraphs from the file parameter in the context.
func createDepGraphs(ictx workflow.InvocationContext) ([]*testapi.IoSnykApiV1testdepgraphRequestDepGraph, []string, error) {
	depGraphResult, err := service.GetDepGraph(ictx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get dependency graph: %w", err)
	}

	if len(depGraphResult.DepGraphBytes) == 0 {
		return nil, nil, fmt.Errorf("no dependency graphs found")
	}

	depGraphs := make([]*testapi.IoSnykApiV1testdepgraphRequestDepGraph, len(depGraphResult.DepGraphBytes))
	for i, depGraphBytes := range depGraphResult.DepGraphBytes {
		var depGraphStruct testapi.IoSnykApiV1testdepgraphRequestDepGraph
		err = json.Unmarshal(depGraphBytes, &depGraphStruct)
		if err != nil {
			return nil, nil,
				fmt.Errorf("unmarshaling depGraph from args failed: %w", err)
		}
		depGraphs[i] = &depGraphStruct
	}

	return depGraphs, depGraphResult.DisplayTargetFiles, nil
}
