package service

import (
	"fmt"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-os-flows/internal/util"

	"github.com/snyk/cli-extension-os-flows/internal/constants"
	"github.com/snyk/cli-extension-os-flows/internal/errors"
)

// NormalisedTargetFileKey is used by the dep graph workflow to embed the target file path in the workflow data.
const NormalisedTargetFileKey = "normalisedTargetFile"

// TargetFileFromPluginKey is used by the dep graph workflow to embed the unnormalised target file path in the workflow data.
const TargetFileFromPluginKey = "targetFileFromPlugin"

// TargetKey is used by the dep graph workflow to embed the target object in the workflow data.
const TargetKey = "target"

// DepGraphWorkflowID is the identifier for the dependency graph workflow.
var DepGraphWorkflowID = workflow.NewWorkflowIdentifier("depgraph")

// ConfigFlagPruneDepGraphs can be passed to the dep graph workflow in order to enable pruning.
var ConfigFlagPruneDepGraphs = "prune-graph"

// RawDepGraphWithMeta contains the results of a dependency graph generation.
type RawDepGraphWithMeta struct {
	Payload              []byte
	NormalisedTargetFile string
	TargetFileFromPlugin *string
	Target               []byte
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
	depGraphConfig.Set(ConfigFlagPruneDepGraphs, true)
	if err != nil {
		return nil, errFactory.NewDepGraphWorkflowError(err)
	}

	logger.Printf("Generating documents for %d depgraph(s)\n", len(depGraphsData))
	depGraphs, err := util.MapWithErr(depGraphsData, WorkflowOutputToRawDepGraphWithMeta)
	if err != nil {
		return nil, errFactory.NewDepGraphWorkflowError(err)
	}

	return depGraphs, nil
}

// WorkflowOutputToRawDepGraphWithMeta converts a workflow output to a RawDepGraphWithMeta.
func WorkflowOutputToRawDepGraphWithMeta(data workflow.Data) (RawDepGraphWithMeta, error) {
	depGraphBytes, err := getPayloadBytes(data)
	if err != nil {
		return RawDepGraphWithMeta{}, err
	}

	displayTargetFile, err := getNormalisedTargetFile(data)
	if err != nil {
		return RawDepGraphWithMeta{}, fmt.Errorf("could not get display target file from depgraph data")
	}

	targetFileFromPlugin := optionalMetaDataString(data, TargetFileFromPluginKey)
	target := optionalMetaDataBytes(data, TargetKey)

	return RawDepGraphWithMeta{
		Payload:              depGraphBytes,
		NormalisedTargetFile: displayTargetFile,
		TargetFileFromPlugin: targetFileFromPlugin,
		Target:               target,
	}, nil
}

func getNormalisedTargetFile(data workflow.Data) (string, error) {
	value, err := data.GetMetaData(NormalisedTargetFileKey)
	if err != nil {
		return "", fmt.Errorf("failed to get dep graph meta field: %w", err)
	}
	return value, nil
}

func getPayloadBytes(data workflow.Data) ([]byte, error) {
	payload := data.GetPayload()
	bytes, ok := payload.([]byte)
	if !ok {
		return nil, fmt.Errorf("invalid payload type (want []byte, got %T)", payload)
	}
	return bytes, nil
}

func optionalMetaDataString(data workflow.Data, key string) *string {
	value, err := data.GetMetaData(key)
	if err != nil {
		return nil
	}
	return &value
}

func optionalMetaDataBytes(data workflow.Data, key string) []byte {
	strValue := optionalMetaDataString(data, key)
	if strValue == nil {
		return nil
	}
	return []byte(*strValue)
}
