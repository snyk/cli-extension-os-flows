package ostest

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	service "github.com/snyk/cli-extension-os-flows/internal/common"
	"github.com/snyk/cli-extension-os-flows/internal/constants"
	"github.com/snyk/cli-extension-os-flows/internal/legacy/definitions"
	"github.com/snyk/cli-extension-os-flows/internal/reachability"
	"github.com/snyk/cli-extension-os-flows/pkg/flags"

	"github.com/google/uuid"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func createDepgraphTmpFiles(depGraphs []service.DepgraphWithIdentity) (rootTmpDir string, tmpFilePaths []string, err error) {
	rootTmpDir, err = os.MkdirTemp("", "snyk-depgraphs-*")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp directory: %w", err)
	}

	paths := make([]string, 0, len(depGraphs))
	for _, dg := range depGraphs {
		tmpFile, err := os.CreateTemp(rootTmpDir, "depgraph-*")
		if err != nil {
			return rootTmpDir, nil, fmt.Errorf("failed to create tmp file for depgraph: %w", err)
		}
		bts, err := json.Marshal(dg)
		if err != nil {
			tmpFile.Close()
			return rootTmpDir, nil, fmt.Errorf("failed to marshal depgraph: %w", err)
		}
		if _, err := tmpFile.Write(bts); err != nil {
			tmpFile.Close()
			return rootTmpDir, nil, fmt.Errorf("failed to write depgraph to tmp file: %w", err)
		}
		tmpFile.Close()
		paths = append(paths, tmpFile.Name())
	}

	return rootTmpDir, paths, nil
}

// RunDflyDepgraphFlow handles the depGraph flow, fully through dragonfly.
func RunDflyDepgraphFlow(
	ctx context.Context,
	inputDir string,
	dgResolver service.DepgraphResolver,
	clients FlowClients,
	orgUUID uuid.UUID,
	localPolicy *testapi.LocalPolicy,
	reachabilityOpts *ReachabilityOpts,
) ([]definitions.LegacyVulnerabilityResponse, []workflow.Data, error) {
	ictx := cmdctx.Ictx(ctx)
	logger := cmdctx.Logger(ctx)
	progressBar := cmdctx.ProgressBar(ctx)
	instrumentation := cmdctx.Instrumentation(ctx)

	logger.Info().Msg("Starting open source test")

	progressBar.SetTitle("Listing dependencies...")

	depGraphs, err := dgResolver.GetDepGraphsWithIdentity(ictx, inputDir)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract dependency graphs: %w", err)
	}

	if len(depGraphs) == 0 {
		return nil, nil, fmt.Errorf("no testable projects found")
	}

	tmpRootDir, paths, err := createDepgraphTmpFiles(depGraphs)
	defer func() {
		tmpDirRmErr := os.RemoveAll(tmpRootDir)
		logger.Warn().Err(tmpDirRmErr).Msg("Failed to clean up temporary directory.")
	}()
	if err != nil {
		return nil, nil, err
	}

	pathsChan := make(chan string)
	go func() {
		for _, path := range paths {
			pathsChan <- path
		}
		close(pathsChan)
	}()

	uploadRes, err := clients.FileUploadClient.CreateRevisionFromChan(ctx, pathsChan, tmpRootDir)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to upload dependency graphs: %w", err)
	}

	cfg := cmdctx.Config(ctx)

	if override := cfg.GetString(flags.FlagProjectName); override != "" {
		for i := range depGraphs {
			depGraphs[i].Identity.Name = override
		}
	}

	scmInfo := ResolveScmInfo(inputDir, cfg.GetString(flags.FlagRemoteRepoURL), logger)

	var scmCtx *testapi.ScmContext
	if scmInfo != nil {
		scmCtx = &testapi.ScmContext{
			RepoUrl: &scmInfo.RemoteURL,
			Branch:  &scmInfo.Branch,
		}
	}

	uploadResource, err := newUploadResource(uploadRes.RevisionID.String(), testapi.UploadResourceContentTypeSbom, scmCtx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create upload resource: %w", err)
	}

	resources := []testapi.TestResourceCreateItem{uploadResource}

	if reachabilityOpts != nil {
		progressBar.SetTitle(constants.UploadingSourceCodeMessage)

		var sourceResource testapi.TestResourceCreateItem
		sourceResource, err = uploadSourceCodeResource(ctx, orgUUID, clients.FileUploadClient, clients.DeeproxyClient, reachabilityOpts.SourceDir)
		if err != nil {
			logger.Warn().Err(err).Msg("Failed to upload source code, proceeding without reachability")
			//nolint:errcheck // Best-effort warning output.
			ictx.GetUserInterface().OutputError(reachability.NewWarning(err))
		} else {
			resources = append(resources, sourceResource)
		}
	}

	testConfig := buildTestConfig(cfg, localPolicy)

	projectName := depGraphs[0].Identity.Name
	targetFile := depGraphs[0].Identity.TargetFile

	osAnalysisStart := time.Now()
	legacyVuln, wfData, err := RunTestWithResources(
		ctx, inputDir, clients.TestClient, resources,
		projectName, "", 0, targetFile, targetFile, orgUUID.String(), testConfig,
	)
	if instrumentation != nil {
		instrumentation.RecordOSAnalysisTime(time.Since(osAnalysisStart).Milliseconds())
	}

	var legacyVulnRes []definitions.LegacyVulnerabilityResponse
	if legacyVuln != nil {
		legacyVulnRes = []definitions.LegacyVulnerabilityResponse{*legacyVuln}
	}

	return legacyVulnRes, wfData, err
}

func buildTestConfig(cfg configuration.Configuration, localPolicy *testapi.LocalPolicy) *testapi.TestConfiguration {
	testConfig := &testapi.TestConfiguration{
		LocalPolicy: localPolicy,
		ScanConfig: &testapi.ScanConfiguration{
			Sca: &testapi.ScaScanConfiguration{},
		},
	}
	if tr := cfg.GetString(flags.FlagTargetReference); tr != "" {
		testConfig.TargetReference = &tr
	}
	return testConfig
}
