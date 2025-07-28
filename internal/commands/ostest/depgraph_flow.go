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
	"github.com/snyk/cli-extension-os-flows/internal/output_workflow"
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
	var allLegacyFindings []definitions.LegacyVulnerabilityResponse
	var allOutputData []workflow.Data

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
		legacyFinding, outputData, err := RunTest(ctx, ictx, testClient, subject, projectName, packageManager, depCount, displayTargetFile, orgID, errFactory, logger, localPolicy)

		if err != nil {
			return nil, err
		}

		if legacyFinding != nil {
			allLegacyFindings = append(allLegacyFindings, *legacyFinding)
		}
		allOutputData = append(allOutputData, outputData...)
	}

	config := ictx.GetConfiguration()
	jsonOutput := config.GetBool("json")
	jsonFileOutput := config.GetString(output_workflow.OUTPUT_CONFIG_KEY_JSON_FILE)

	// Human-readable output is suppressed only when --json is specified.
	wantsHumanReadable := !jsonOutput

	var finalOutput []workflow.Data
	if wantsHumanReadable {
		outputDestination := output_workflow.NewOutputDestination()
		// The output workflow returns data it did not handle, like test summaries for exit code calculation.
		remainingData, err := output_workflow.OutputWorkflowEntryPoint(ictx, allOutputData, outputDestination)
		if err != nil {
			return nil, err
		}
		finalOutput = append(finalOutput, remainingData...)
	}

	// Handle JSON output to a file or stdout.
	wantsJSONFile := jsonFileOutput != ""
	wantsJSONStdOut := jsonOutput

	if wantsJSONFile || wantsJSONStdOut {
		if len(allLegacyFindings) > 0 {
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
			if err = encoder.Encode(findingsData); err != nil {
				return nil, errFactory.NewLegacyJSONTransformerError(fmt.Errorf("marshaling to json: %w", err))
			}
			// encoder.Encode adds a newline, which we trim to match Marshal's behavior.
			findingsBytes := bytes.TrimRight(buffer.Bytes(), "\n")

			if wantsJSONFile {
				if err := os.WriteFile(jsonFileOutput, findingsBytes, 0644); err != nil {
					return nil, fmt.Errorf("failed to write JSON output to file: %w", err)
				}
			}

			if wantsJSONStdOut {
				finalOutput = append(finalOutput, NewWorkflowData(ApplicationJSONContentType, findingsBytes))
			}
		}
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
