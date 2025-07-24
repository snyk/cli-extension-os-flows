package service

import (
	"encoding/json"
	"fmt"

	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-os-flows/internal/errors"
)

// ContentLocationKey is the workflow data's local file relative to its scan path.
const ContentLocationKey string = "Content-Location"

// DepGraphWorkflowID is the identifier for the dependency graph workflow.
var DepGraphWorkflowID = workflow.NewWorkflowIdentifier("depgraph")

// DepGraphResult contains the results of a dependency graph generation.
type DepGraphResult struct {
	DisplayTargetFiles []string
	DepGraphBytes      []json.RawMessage
}

// GetDepGraph retrieves the dependency graph for the given invocation context.
func GetDepGraph(ictx workflow.InvocationContext) (*DepGraphResult, error) {
	engine := ictx.GetEngine()
	config := ictx.GetConfiguration()
	logger := ictx.GetEnhancedLogger()
	errFactory := errors.NewErrorFactory(logger)

	logger.Println("Invoking depgraph workflow")

	depGraphConfig := config.Clone()
	depGraphs, err := engine.InvokeWithConfig(DepGraphWorkflowID, depGraphConfig)
	if err != nil {
		return nil, errFactory.NewDepGraphWorkflowError(err)
	}

	numGraphs := len(depGraphs)
	logger.Printf("Generating documents for %d depgraph(s)\n", numGraphs)
	depGraphBytesList := make([]json.RawMessage, numGraphs)
	displayTargetFiles := make([]string, numGraphs)
	for i, depGraph := range depGraphs {
		depGraphBytes, err := getPayloadBytes(depGraph)
		if err != nil {
			return nil, errFactory.NewDepGraphWorkflowError(err)
		}
		depGraphBytesList[i] = depGraphBytes

		displayTargetFile, err := getContentLocation(depGraph)
		if err != nil {
			logger.Warn().Err(err).Msg("could not get display target file from depgraph data")
			displayTargetFile = ""
		}
		displayTargetFiles[i] = displayTargetFile
	}

	return &DepGraphResult{
		DisplayTargetFiles: displayTargetFiles,
		DepGraphBytes:      depGraphBytesList,
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
