package service

import (
	"encoding/json"
	"fmt"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-os-flows/internal/util"

	"github.com/snyk/cli-extension-os-flows/internal/constants"
	"github.com/snyk/cli-extension-os-flows/internal/errors"
)

// ContentLocationKey is the workflow data's local file relative to its scan path.
const ContentLocationKey string = "Content-Location"

// DepGraphWorkflowID is the identifier for the dependency graph workflow.
var DepGraphWorkflowID = workflow.NewWorkflowIdentifier("depgraph")

// RawDepGraphWithMeta contains the results of a dependency graph generation.
type RawDepGraphWithMeta struct {
	DisplayTargetFile string
	Payload           json.RawMessage
}

// GetDepGraph retrieves the dependency graph for the given invocation context.
func GetDepGraph(ictx workflow.InvocationContext, inputDir string) ([]RawDepGraphWithMeta, error) {
	engine := ictx.GetEngine()
	config := ictx.GetConfiguration()
	logger := ictx.GetEnhancedLogger()
	errFactory := errors.NewErrorFactory(logger)

	depGraphConfig := config.Clone()
	experimentalUvSupportEnabled := config.GetBool(constants.EnableExperimentalUvSupportEnvVar)

	if experimentalUvSupportEnabled {
		logger.Info().Msg("Experimental uv support enabled, using SBOM resolution in depgraph workflow")
		depGraphConfig.Set("use-sbom-resolution", true)
	} else {
		logger.Println("Invoking depgraph workflow")
	}

	// Overriding the INPUT_DIRECTORY flag which the depgraph workflow will use to extract the depgraphs.
	depGraphConfig.Set(configuration.INPUT_DIRECTORY, inputDir)
	depGraphsData, err := engine.InvokeWithConfig(DepGraphWorkflowID, depGraphConfig)
	if err != nil {
		return nil, errFactory.NewDepGraphWorkflowError(err)
	}

	logger.Printf("Generating documents for %d depgraph(s)\n", len(depGraphsData))
	depGraphs, err := util.MapWithErr(depGraphsData, workflowOutputToRawDepGraphWithMeta)
	if err != nil {
		return nil, errFactory.NewDepGraphWorkflowError(err)
	}

	return depGraphs, nil
}

func workflowOutputToRawDepGraphWithMeta(data workflow.Data) (RawDepGraphWithMeta, error) {
	depGraphBytes, err := getPayloadBytes(data)
	if err != nil {
		return RawDepGraphWithMeta{}, err
	}

	displayTargetFile, err := getContentLocation(data)
	if err != nil {
		return RawDepGraphWithMeta{}, fmt.Errorf("could not get display target file from depgraph data")
	}

	return RawDepGraphWithMeta{
		Payload:           depGraphBytes,
		DisplayTargetFile: displayTargetFile,
	}, nil
}

func getContentLocation(data workflow.Data) (string, error) {
	location, err := data.GetMetaData(ContentLocationKey)
	if err != nil {
		return "", fmt.Errorf("failed to get content location: %w", err)
	}
	return location, nil
}

func getPayloadBytes(data workflow.Data) ([]byte, error) {
	payload := data.GetPayload()
	bytes, ok := payload.([]byte)
	if !ok {
		return nil, fmt.Errorf("invalid payload type (want []byte, got %T)", payload)
	}
	return bytes, nil
}
