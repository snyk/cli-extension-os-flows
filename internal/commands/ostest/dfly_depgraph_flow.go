package ostest

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	"github.com/snyk/cli-extension-os-flows/internal/fileupload"
	"github.com/snyk/cli-extension-os-flows/internal/legacy/definitions"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

type identity struct {
	Name string `json:"name"`
	Type string `json:"type"`
	// Do we need the relative one as well?
	TargetFile    string  `json:"targetFile"`
	TargetRuntime *string `json:"targetRuntime"`
}

type depGraphWitIdentity struct {
	DepGraph *testapi.IoSnykApiV1testdepgraphRequestDepGraph `json:"depGraph"`
	Identity identity                                        `json:"identity"`
}

func createDepgraphTmpFiles(depGraphs []DepGraphWithMeta) ([]string, error) {
	paths := make([]string, 0, len(depGraphs))
	for _, dg := range depGraphs {
		tmpFile, err := os.CreateTemp("", "snyk-depgraph-*")
		if err != nil {
			return nil, fmt.Errorf("failed to create tmp file for depgraph: %w", err)
		}
		//TODO: Fill identity
		bts, err := json.Marshal(depGraphWitIdentity{DepGraph: dg.Payload, Identity: identity{}})
		if err != nil {
			tmpFile.Close()
			return nil, fmt.Errorf("failed to marshal depgraph: %w", err)
		}
		if _, err := tmpFile.Write(bts); err != nil {
			tmpFile.Close()
			return nil, fmt.Errorf("failed to write depgraph to tmp file: %w", err)
		}
		tmpFile.Close()
		paths = append(paths, tmpFile.Name())
	}

	return paths, nil
}

func RunDflyDepgraphFlow(
	ctx context.Context,
	inputDir string,
	fuClient fileupload.Client,
	testClient testapi.TestClient,
	orgID string,
	localPolicy *testapi.LocalPolicy,
) ([]definitions.LegacyVulnerabilityResponse, []workflow.Data, error) {
	ictx := cmdctx.Ictx(ctx)
	// cfg := cmdctx.Config(ctx)
	logger := cmdctx.Logger(ctx)
	progressBar := cmdctx.ProgressBar(ctx)
	// instrumentation := cmdctx.Instrumentation(ctx)

	logger.Info().Msg("Starting open source test")

	progressBar.SetTitle("Listing dependencies...")
	// Create depgraphs and get their associated target files
	depgraphs, err := createDepGraphs(ictx, inputDir)
	if err != nil {
		return nil, nil, err
	}

	paths, err := createDepgraphTmpFiles(depgraphs)
	if err != nil {
		return nil, nil, err
	}

	uploadRes, err := fuClient.CreateRevisionFromPaths(ctx, paths, fileupload.UploadOptions{})
	if err != nil {
		return nil, nil, err
	}

	uploadResource, err := newUploadResource(uploadRes.RevisionID.String(), testapi.UploadResourceContentTypeSbom)
	if err != nil {
		return nil, nil, err
	}

	resources := []testapi.TestResourceCreateItem{uploadResource}
	scanConfig := &testapi.ScanConfiguration{
		Sca: &testapi.ScaScanConfiguration{},
	}

	legacyVuln, wfData, err := RunTestWithResources(ctx, inputDir, testClient, resources, "", "", 0, "", "", orgID, localPolicy, scanConfig)

	return []definitions.LegacyVulnerabilityResponse{*legacyVuln}, wfData, err
}
