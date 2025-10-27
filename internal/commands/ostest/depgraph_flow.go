package ostest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/content_type"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"golang.org/x/sync/errgroup"

	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	service "github.com/snyk/cli-extension-os-flows/internal/common"
	"github.com/snyk/cli-extension-os-flows/internal/flags"
	"github.com/snyk/cli-extension-os-flows/internal/legacy/definitions"
	"github.com/snyk/cli-extension-os-flows/internal/outputworkflow"
	"github.com/snyk/cli-extension-os-flows/internal/reachability"
)

const maxConcurrentTests = 5

const (
	scanIDField       = "reachabilityScanId"
	ignorePolicyField = "ignorePolicy"
)

func enrichWithScanID(depgraphs []*testapi.IoSnykApiV1testdepgraphRequestDepGraph, reachabilityScanID *reachability.ID) {
	if reachabilityScanID == nil {
		return
	}

	for _, dg := range depgraphs {
		dg.Set(scanIDField, reachabilityScanID.String())
	}
}

func enrichWithIgnorePolicy(depgraphs []*testapi.IoSnykApiV1testdepgraphRequestDepGraph, ignorePolicy bool) {
	if !ignorePolicy {
		return
	}

	for _, dg := range depgraphs {
		dg.Set(ignorePolicyField, ignorePolicy)
	}
}

// RunUnifiedTestFlow handles the unified test API flow.
func RunUnifiedTestFlow(
	ctx context.Context,
	inputDir string,
	testClient testapi.TestClient,
	orgID string,
	localPolicy *testapi.LocalPolicy,
	reachabilityScanID *reachability.ID,
) ([]definitions.LegacyVulnerabilityResponse, []workflow.Data, error) {
	ictx := cmdctx.Ictx(ctx)
	cfg := cmdctx.Config(ctx)
	logger := cmdctx.Logger(ctx)
	progressBar := cmdctx.ProgressBar(ctx)

	logger.Info().Msg("Starting open source test")

	progressBar.SetTitle("Listing dependencies...")
	// Create depgraphs and get their associated target files
	depGraphs, displayTargetFiles, err := createDepGraphs(ictx, inputDir)
	if err != nil {
		return nil, nil, err
	}

	enrichWithScanID(depGraphs, reachabilityScanID)
	enrichWithIgnorePolicy(depGraphs, cfg.GetBool(flags.FlagIgnorePolicy))

	allLegacyFindings, allOutputData, err := testAllDepGraphs(
		ctx,
		inputDir,
		testClient,
		orgID,
		localPolicy,
		depGraphs,
		displayTargetFiles,
	)
	if err != nil {
		return nil, nil, err
	}

	return allLegacyFindings, allOutputData, err
}

// testProcessor contains the context and dependencies for running a depGraph test.
type testProcessor struct {
	testClient  testapi.TestClient
	orgID       string
	localPolicy *testapi.LocalPolicy
}

// runDepGraphTest runs a test for a single depGraph.
func (p *testProcessor) runDepGraphTest(
	ctx context.Context,
	targetDir string,
	depGraph *testapi.IoSnykApiV1testdepgraphRequestDepGraph,
	displayTargetFile string,
) (*definitions.LegacyVulnerabilityResponse, []workflow.Data, error) {
	subject, err := createTestSubject(depGraph, displayTargetFile)
	if err != nil {
		return nil, nil, err
	}

	projectName := getProjectName(ctx, depGraph)
	packageManager := depGraph.PkgManager.Name
	depCount := max(0, len(depGraph.Pkgs)-1)

	return RunTest(
		ctx, targetDir, p.testClient, subject, projectName, packageManager, depCount,
		displayTargetFile, p.orgID, p.localPolicy,
	)
}

// testAllDepGraphs tests depGraphs in parallel, up to maxConcurrency at a time, until completion or error.
// Returns legacy JSON and/or human-readable workflow data, depending on parameters.
func testAllDepGraphs(
	ctx context.Context,
	targetDir string,
	testClient testapi.TestClient,
	orgID string,
	localPolicy *testapi.LocalPolicy,
	depGraphs []*testapi.IoSnykApiV1testdepgraphRequestDepGraph,
	displayTargetFiles []string,
) ([]definitions.LegacyVulnerabilityResponse, []workflow.Data, error) {
	cfg := cmdctx.Config(ctx)
	logger := cmdctx.Logger(ctx)
	g, gctx := errgroup.WithContext(ctx)

	numThreads := maxConcurrentTests
	maxThreads := cfg.GetInt(configuration.MAX_THREADS)
	if maxThreads > 0 {
		numThreads = min(maxThreads, maxConcurrentTests)
	}
	g.SetLimit(numThreads)

	processor := &testProcessor{
		testClient:  testClient,
		orgID:       orgID,
		localPolicy: localPolicy,
	}

	findingsByIdx := make([]*definitions.LegacyVulnerabilityResponse, len(depGraphs))
	outputsByIdx := make([][]workflow.Data, len(depGraphs))

	for i := range depGraphs {
		g.Go(func() (err error) {
			defer func() {
				if pErr := recover(); pErr != nil {
					logger.Error().Err(fmt.Errorf("panic: %v", pErr)).Msg("unexpected error occurred")
					err = errors.Join(err, errors.New("unexpected error occurred"))
				}
			}()
			depGraph := depGraphs[i]
			displayTargetFile := ""
			if i < len(displayTargetFiles) {
				displayTargetFile = displayTargetFiles[i]
			}

			legacyFinding, outputData, err := processor.runDepGraphTest(gctx, targetDir, depGraph, displayTargetFile)
			if err != nil {
				return err
			}

			if legacyFinding != nil {
				findingsByIdx[i] = legacyFinding
			}
			outputsByIdx[i] = outputData

			return err
		})
	}

	if err := g.Wait(); err != nil {
		return nil, nil, fmt.Errorf("testing depgraphs: %w", err)
	}

	allLegacyFindings := make([]definitions.LegacyVulnerabilityResponse, 0, len(depGraphs))
	var allOutputData []workflow.Data
	for i := range findingsByIdx {
		if findingsByIdx[i] != nil {
			allLegacyFindings = append(allLegacyFindings, *findingsByIdx[i])
		}
		allOutputData = append(allOutputData, outputsByIdx[i]...)
	}

	return allLegacyFindings, allOutputData, nil
}

// createTestSubject creates a test subject from a depGraph and display target file.
func createTestSubject(
	depGraph *testapi.IoSnykApiV1testdepgraphRequestDepGraph,
	displayTargetFile string,
) (testapi.TestSubjectCreate, error) {
	depGraphSubject := testapi.DepGraphSubjectCreate{
		Type:     testapi.DepGraphSubjectCreateTypeDepGraph,
		DepGraph: *depGraph,
		Locator: testapi.LocalPathLocator{
			Paths: []string{displayTargetFile},
			Type:  testapi.LocalPath,
		},
	}

	var subject testapi.TestSubjectCreate
	err := subject.FromDepGraphSubjectCreate(depGraphSubject)
	if err != nil {
		return subject, fmt.Errorf("failed to create test subject: %w", err)
	}
	return subject, nil
}

func getProjectName(
	ctx context.Context,
	depGraph *testapi.IoSnykApiV1testdepgraphRequestDepGraph,
) string {
	cfg := cmdctx.Config(ctx)
	// Project name assigned as follows: --project-name || config project name || scannedProject?.depTree?.name
	// TODO: use project name from Config file
	projectName := cfg.GetString(flags.FlagProjectName)
	if projectName == "" && len(depGraph.Pkgs) > 0 {
		projectName = depGraph.Pkgs[0].Info.Name
	}
	return projectName
}

// handleOutput processes both legacy JSON and human-readable findings into their respective outputs.
// Human-readable output is processed by the local template renderer.
// JSON file output is written to file here, while JSON stdout is added to the output workflow.
// Summary data is added to the output workflow for exit code calculation.
func handleOutput(
	ctx context.Context,
	allLegacyFindings []definitions.LegacyVulnerabilityResponse,
	allOutputData []workflow.Data,
) ([]workflow.Data, error) {
	ictx := cmdctx.Ictx(ctx)
	cfg := cmdctx.Config(ctx)
	jsonOutput := cfg.GetBool(outputworkflow.OutputConfigKeyJSON)
	jsonFileOutput := cfg.GetString(outputworkflow.OutputConfigKeyJSONFile)

	// Human-readable output is suppressed only when --json is specified.
	wantsHumanReadable := !jsonOutput
	wantsJSONFile := jsonFileOutput != ""
	wantsJSONStdOut := jsonOutput

	var finalOutput []workflow.Data
	if wantsHumanReadable {
		outputDestination := outputworkflow.NewOutputDestination()
		// The output workflow returns data it did not handle, like test summaries for exit code calculation.
		//nolint:contextcheck // The outputworkflow.EntryPoint call chain is not context-aware
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

	jsonBytes, err := prepareJSONOutput(ctx, allLegacyFindings)
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

// prepareJSONOutput prepares legacy JSON output from findings.
func prepareJSONOutput(
	ctx context.Context,
	allLegacyFindings []definitions.LegacyVulnerabilityResponse,
) ([]byte, error) {
	errFactory := cmdctx.ErrorFactory(ctx)

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
func createDepGraphs(ictx workflow.InvocationContext, inputDir string) ([]*testapi.IoSnykApiV1testdepgraphRequestDepGraph, []string, error) {
	depGraphResult, err := service.GetDepGraph(ictx, inputDir)
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
