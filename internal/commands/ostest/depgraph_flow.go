package ostest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"golang.org/x/sync/errgroup"

	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	"github.com/snyk/cli-extension-os-flows/internal/common"
	"github.com/snyk/cli-extension-os-flows/internal/constants"
	"github.com/snyk/cli-extension-os-flows/internal/legacy/definitions"
	"github.com/snyk/cli-extension-os-flows/internal/outputworkflow"
	"github.com/snyk/cli-extension-os-flows/internal/reachability"
	"github.com/snyk/cli-extension-os-flows/internal/util"
	"github.com/snyk/cli-extension-os-flows/pkg/flags"
)

const maxConcurrentTests = 5

const (
	scanIDField              = "reachabilityScanId"
	ignorePolicyField        = "ignorePolicy"
	projectNameOverrideField = "projectNameOverride"
	targetReferenceField     = "targetReference"
)

func enrichWithScanID(depgraphs []DepGraphWithMeta, reachabilityScanID *reachability.ID) {
	if reachabilityScanID == nil {
		return
	}

	for _, dg := range depgraphs {
		dg.Payload.Set(scanIDField, reachabilityScanID.String())
	}
}

func enrichWithIgnorePolicy(depgraphs []DepGraphWithMeta, ignorePolicy bool) {
	if !ignorePolicy {
		return
	}

	for _, dg := range depgraphs {
		dg.Payload.Set(ignorePolicyField, ignorePolicy)
	}
}

func enrichWithProjectNameOverride(depgraphs []DepGraphWithMeta, projectName string) {
	if projectName == "" {
		return
	}

	for _, dg := range depgraphs {
		dg.Payload.Set(projectNameOverrideField, projectName)
	}
}

func enrichWithTargetReference(depgraphs []DepGraphWithMeta, targetReference string) {
	if targetReference == "" {
		return
	}

	for _, dg := range depgraphs {
		dg.Payload.Set(targetReferenceField, targetReference)
	}
}

// RunUnifiedTestFlow handles the unified test API flow.
func RunUnifiedTestFlow(
	ctx context.Context,
	inputDir string,
	clients common.FlowClients,
	orgUUID uuid.UUID,
	localPolicy *testapi.LocalPolicy,
	reachabilityOpts *common.ReachabilityOpts,
) ([]definitions.LegacyVulnerabilityResponse, []workflow.Data, error) {
	ictx := cmdctx.Ictx(ctx)
	cfg := cmdctx.Config(ctx)
	logger := cmdctx.Logger(ctx)
	progressBar := cmdctx.ProgressBar(ctx)
	instrumentation := cmdctx.Instrumentation(ctx)

	logger.Info().Msg("Starting open source test")

	progressBar.SetTitle("Listing dependencies...")
	depGraphs, err := createDepGraphs(ictx, inputDir)
	if err != nil {
		return nil, nil, err
	}

	if reachabilityOpts != nil {
		progressBar.SetTitle(constants.UploadingSourceCodeMessage)

		scanID, scanErr := reachability.GetReachabilityID(
			ctx,
			orgUUID,
			reachabilityOpts.SourceDir,
			clients.ReachabilityClient,
			clients.FileUploadClient,
			clients.DeeproxyClient,
		)
		if scanErr != nil {
			logger.Warn().Err(scanErr).Msg("Reachability analysis failed, proceeding without reachability")
			//nolint:errcheck // Best-effort warning output.
			ictx.GetUserInterface().OutputError(reachability.NewWarning(scanErr))
		} else {
			enrichWithScanID(depGraphs, &scanID)
		}
	}
	enrichWithIgnorePolicy(depGraphs, cfg.GetBool(flags.FlagIgnorePolicy))
	enrichWithProjectNameOverride(depGraphs, cfg.GetString(flags.FlagProjectName))
	enrichWithTargetReference(depGraphs, cfg.GetString(flags.FlagTargetReference))

	osAnalysisStart := time.Now()
	allLegacyFindings, allOutputData, err := testAllDepGraphs(
		ctx,
		inputDir,
		clients.TestClient,
		orgUUID.String(),
		localPolicy,
		depGraphs,
	)
	if err != nil {
		return nil, nil, err
	}
	if instrumentation != nil {
		instrumentation.RecordOSAnalysisTime(time.Since(osAnalysisStart).Milliseconds())
	}

	return allLegacyFindings, allOutputData, err
}

type testProcessor struct {
	testClient  testapi.TestClient
	orgID       string
	localPolicy *testapi.LocalPolicy
}

func (p *testProcessor) runDepGraphTest(
	ctx context.Context,
	targetDir string,
	depGraph DepGraphWithMeta,
) (*definitions.LegacyVulnerabilityResponse, []workflow.Data, error) {
	subject, err := createTestSubject(depGraph)
	if err != nil {
		return nil, nil, err
	}

	projectName := getProjectName(ctx, depGraph)
	packageManager := depGraph.Payload.PkgManager.Name
	depCount := max(0, len(depGraph.Payload.Pkgs)-1)

	return RunTestWithSubject(
		ctx,
		targetDir,
		p.testClient,
		subject,
		projectName,
		packageManager,
		depCount,
		depGraph.TargetFileFromPlugin,
		depGraph.DisplayTargetFile,
		p.orgID,
		p.localPolicy,
	)
}

func testAllDepGraphs(
	ctx context.Context,
	targetDir string,
	testClient testapi.TestClient,
	orgID string,
	localPolicy *testapi.LocalPolicy,
	depGraphs []DepGraphWithMeta,
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
					logger.Error().Stack().Err(fmt.Errorf("panic: %v", pErr)).Msg("unexpected error occurred")
					err = errors.Join(err, errors.New("unexpected error occurred"))
				}
			}()
			depGraph := depGraphs[i]

			legacyFinding, outputData, err := processor.runDepGraphTest(gctx, targetDir, depGraph)
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

func createTestSubject(depGraph DepGraphWithMeta) (testapi.TestSubjectCreate, error) {
	depGraphSubject := testapi.DepGraphSubjectCreate{
		Type:     testapi.DepGraph,
		DepGraph: *depGraph.Payload,
		Locator: testapi.LocalPathLocator{
			Paths: []string{depGraph.DisplayTargetFile},
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

func getProjectName(ctx context.Context, depGraph DepGraphWithMeta) string {
	cfg := cmdctx.Config(ctx)
	projectName := cfg.GetString(flags.FlagProjectName)
	if projectName == "" && len(depGraph.Payload.Pkgs) > 0 {
		projectName = depGraph.Payload.Pkgs[0].Info.Name
	}
	return projectName
}

func handleOutput(
	ctx context.Context,
	allLegacyFindings []definitions.LegacyVulnerabilityResponse,
	allOutputData []workflow.Data,
) ([]workflow.Data, error) {
	ictx := cmdctx.Ictx(ctx)
	cfg := cmdctx.Config(ctx)
	jsonOutput := cfg.GetBool(outputworkflow.OutputConfigKeyJSON)
	jsonFileOutput := cfg.GetString(outputworkflow.OutputConfigKeyJSONFile)

	wantsHumanReadable := !jsonOutput
	wantsJSONFile := jsonFileOutput != ""
	wantsJSONStdOut := jsonOutput

	var finalOutput []workflow.Data
	if wantsHumanReadable {
		outputDestination := outputworkflow.NewOutputDestination()
		//nolint:contextcheck // The outputworkflow.EntryPoint call chain is not context-aware.
		remainingData, err := outputworkflow.EntryPoint(ictx, allOutputData, outputDestination)
		if err != nil {
			return nil, fmt.Errorf("failed to process output workflow: %w", err)
		}
		finalOutput = append(finalOutput, remainingData...)
	}

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
		return append(allOutputData, NewWorkflowData(ApplicationJSONContentType, jsonBytes)), nil
	}

	return finalOutput, nil
}

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
	return bytes.TrimRight(buffer.Bytes(), "\n"), nil
}

func createDepGraphs(ictx workflow.InvocationContext, inputDir string) ([]DepGraphWithMeta, error) {
	rawDepGraphs, err := common.GetDepGraph(ictx, inputDir)
	if err != nil {
		return nil, fmt.Errorf("failed to get dependency graph: %w", err)
	}

	if len(rawDepGraphs) == 0 {
		return nil, fmt.Errorf("no dependency graphs found")
	}

	//nolint:wrapcheck // Error from ParseDepGraph is already descriptive
	return util.MapWithErr(rawDepGraphs, ParseDepGraph)
}

// ParseDepGraph parses a raw depgraph into a DepGraphWithMeta.
func ParseDepGraph(rawDepGraph common.RawDepGraphWithMeta) (DepGraphWithMeta, error) {
	var targetFile string
	var payload testapi.IoSnykApiV1testdepgraphRequestDepGraph
	err := json.Unmarshal(rawDepGraph.Payload, &payload)
	if err != nil {
		return DepGraphWithMeta{}, fmt.Errorf("unmarshaling depGraph from args failed: %w", err)
	}

	if payload.AdditionalProperties == nil {
		payload.AdditionalProperties = map[string]interface{}{}
	}
	if rawDepGraph.TargetFileFromPlugin != nil {
		targetFile = *rawDepGraph.TargetFileFromPlugin
		payload.Set("targetFile", targetFile)
	}
	if rawDepGraph.Target != nil {
		payload.Set("target", json.RawMessage(rawDepGraph.Target))
	}

	return DepGraphWithMeta{
		Payload:              &payload,
		DisplayTargetFile:    rawDepGraph.NormalisedTargetFile,
		TargetFileFromPlugin: targetFile,
	}, nil
}

// DepGraphWithMeta encapsulates a dependency graph and its metadata.
type DepGraphWithMeta struct {
	Payload              *testapi.IoSnykApiV1testdepgraphRequestDepGraph
	DisplayTargetFile    string
	TargetFileFromPlugin string
}
