package service

import (
	"encoding/json"
	"fmt"

	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-os-flows/internal/errors"
)

// DepGraphWorkflowID is the identifier for the dependency graph workflow.
var DepGraphWorkflowID = workflow.NewWorkflowIdentifier("depgraph")

// DepGraphResult contains the results of a dependency graph generation.
type DepGraphResult struct {
	Name          string
	DepGraphBytes []json.RawMessage
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
	depGraphsBytes := make([]json.RawMessage, numGraphs)
	for i, depGraph := range depGraphs {
		depGraphBytes, err := getPayloadBytes(depGraph)
		if err != nil {
			return nil, errFactory.NewDepGraphWorkflowError(err)
		}
		depGraphsBytes[i] = depGraphBytes
	}

	return &DepGraphResult{
		Name:          "",
		DepGraphBytes: depGraphsBytes,
	}, nil
}

func getPayloadBytes(data workflow.Data) ([]byte, error) {
	payload := data.GetPayload()
	bytes, ok := payload.([]byte)
	if !ok {
		return nil, fmt.Errorf("invalid payload type (want []byte, got %T)", payload)
	}
	return bytes, nil
}
