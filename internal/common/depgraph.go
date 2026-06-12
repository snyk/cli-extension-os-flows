package common

import (
	"encoding/json"
	stderrors "errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/snyk/error-catalog-golang-public/snyk_errors"

	"github.com/rs/zerolog"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/orchestrator"
	uvutils "github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/python/uv"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-os-flows/internal/constants"
	"github.com/snyk/cli-extension-os-flows/internal/errors"
	"github.com/snyk/cli-extension-os-flows/internal/util"
	"github.com/snyk/cli-extension-os-flows/pkg/flags"
)

// NormalisedTargetFileKey is used by the dep graph workflow to embed the target file path in the workflow data.
const NormalisedTargetFileKey = "normalisedTargetFile"

// TargetFileFromPluginKey is used by the dep graph workflow to embed the unnormalised target file path in the workflow data.
const TargetFileFromPluginKey = "targetFileFromPlugin"

// TargetKey is used by the dep graph workflow to embed the target object in the workflow data.
const TargetKey = "target"

// DepGraphWorkflowID is the identifier for the dependency graph workflow.
var DepGraphWorkflowID = workflow.NewWorkflowIdentifier("depgraph")

// ConfigFlagEffectiveDepGraphs can be passed to the dep graph workflow in order to enable effective, possibly pruned dependency graphs.
var ConfigFlagEffectiveDepGraphs = "effective-graph"

// RawDepGraphWithMeta contains the results of a dependency graph generation.
type RawDepGraphWithMeta struct {
	Payload              []byte
	NormalisedTargetFile string
	TargetFileFromPlugin *string
	Target               []byte
}

// GetDepGraph retrieves the dependency graph for the given invocation context.
//
// Priority: uv handling (uv.lock + FeatureFlagUvCLI) takes precedence over the unified-test-api
// orchestrator path so that uv repos keep their SBOM-resolution behavior as the unified FF rolls out.
func GetDepGraph(ictx workflow.InvocationContext, inputDir string) ([]RawDepGraphWithMeta, error) {
	config := ictx.GetConfiguration()
	logger := ictx.GetEnhancedLogger()
	errFactory := errors.NewErrorFactory(logger)

	allProjects := config.GetBool(flags.FlagAllProjects)
	fileFlag := config.GetString(flags.FlagFile)

	// FeatureFlagUvCLI is only looked up when uv.lock is present, matching the prior cascading check.
	uvLockExists := uvutils.HasUvLockFile(inputDir, fileFlag, allProjects, logger)
	useUv := uvLockExists && config.GetBool(constants.FeatureFlagUvCLI)

	if !useUv && config.GetBool(orchestrator.FlagUnifiedTestAPIOsCLI.Key) {
		logger.Info().Msgf("Using unifed scanners")
		return resolveViaOrchestrator(ictx, inputDir, errFactory)
	}
	return resolveViaWorkflow(ictx, inputDir, useUv, uvLockExists, errFactory)
}

func resolveViaOrchestrator(
	ictx workflow.InvocationContext,
	inputDir string,
	errFactory *errors.ErrorFactory,
) ([]RawDepGraphWithMeta, error) {
	config := ictx.GetConfiguration()
	opts, err := ecosystems.NewPluginOptionsFromRawFlags(config.GetStringSlice(configuration.RAW_CMD_ARGS))
	if err != nil {
		return nil, errFactory.NewDepGraphWorkflowError(err)
	}
	return getDepgraphsFromOrchestrator(ictx, inputDir, opts)
}

func resolveViaWorkflow(
	ictx workflow.InvocationContext,
	inputDir string,
	useUv, uvLockExists bool,
	errFactory *errors.ErrorFactory,
) ([]RawDepGraphWithMeta, error) {
	engine := ictx.GetEngine()
	config := ictx.GetConfiguration()
	logger := ictx.GetEnhancedLogger()

	depGraphConfig := config.Clone()
	switch {
	case useUv:
		logger.Info().Msg("uv support enabled and uv.lock found, using SBOM resolution in depgraph workflow")
		depGraphConfig.Set("use-sbom-resolution", true)
	case uvLockExists:
		logger.Info().Msg("uv.lock found but uv feature flag disabled, using standard depgraph workflow")
	default:
		logger.Info().Msg("Invoking depgraph workflow")
	}

	// Overriding the INPUT_DIRECTORY flag which the depgraph workflow will use to extract the depgraphs.
	depGraphConfig.Set(configuration.INPUT_DIRECTORY, inputDir)
	depGraphConfig.Set(ConfigFlagEffectiveDepGraphs, true)
	depGraphsData, err := engine.InvokeWithConfig(DepGraphWorkflowID, depGraphConfig)
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

func getDepgraphsFromOrchestrator(ictx workflow.InvocationContext, inputDir string, opts *ecosystems.SCAPluginOptions) ([]RawDepGraphWithMeta, error) {
	registry, err := orchestrator.NewDefaultPluginRegistry(ictx)
	if err != nil {
		return nil, fmt.Errorf("failed to create plugin registry: %w", err)
	}

	results := registry.ResolveDepgraphs(inputDir, opts)

	logger := ictx.GetEnhancedLogger()
	config := ictx.GetConfiguration()
	target := resolveTarget(inputDir, config.GetString(flags.FlagRemoteRepoURL), logger)

	allProjects := config.GetBool(flags.FlagAllProjects)

	rawDepGraphs := make([]RawDepGraphWithMeta, 0)
	var failedErrors []error
	for result := range results {
		if result.Error != nil && allProjects {
			// With --all-projects, a single ecosystem failing to resolve
			// (e.g. missing tooling for Python) should not abort the entire
			// scan. Accumulate failures and only error if all projects fail,
			// matching the legacy TS CLI behavior.
			//
			// Format the message to match legacy output:
			//   <file>:
			//     <error detail>
			targetFile := ""
			if result.ResolverMetadata != nil && result.ResolverMetadata.NormalisedTargetFile != "" {
				targetFile = filepath.Join(inputDir, result.ResolverMetadata.NormalisedTargetFile)
			}
			errMsg := extractErrorDetail(result.Error)
			if targetFile != "" {
				failedErrors = append(failedErrors, fmt.Errorf("%s:\n  %s", targetFile, errMsg))
			} else {
				failedErrors = append(failedErrors, fmt.Errorf("%s", errMsg))
			}
			continue
		}

		dg, err := mapToRawDepGraphWithMeta(&result, target)
		if err != nil {
			return nil, err
		}
		rawDepGraphs = append(rawDepGraphs, *dg)
	}

	total := len(rawDepGraphs) + len(failedErrors)

	if len(failedErrors) > 0 {
		msgs := make([]string, 0, len(failedErrors))
		for _, e := range failedErrors {
			msgs = append(msgs, e.Error())
		}
		failureSummary := strings.Join(msgs, "\n\n")

		if len(rawDepGraphs) == 0 {
			// All projects failed.
			return nil, fmt.Errorf("failed to get dependencies for all %d potential projects.\n\n%s",
				total, failureSummary)
		}

		// Partial failure: some projects resolved, some did not.
		// Use the UI layer so the message is always visible, matching the
		// legacy TS CLI which prints these warnings unconditionally.
		//nolint:errcheck // Best-effort warning output.
		ictx.GetUserInterface().OutputError(
			fmt.Errorf("\n%s\n✗ %d/%d potential projects failed to get dependencies",
				failureSummary, len(failedErrors), total))
	}

	if len(rawDepGraphs) == 0 {
		return nil, fmt.Errorf("no testable projects found")
	}
	return rawDepGraphs, nil
}

func resolveTarget(inputDir, remoteRepoURL string, logger *zerolog.Logger) []byte {
	scmInfo := ResolveScmInfo(inputDir, remoteRepoURL, logger)
	if scmInfo == nil {
		return nil
	}
	target, err := json.Marshal(scmInfo)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to marshal SCM info, proceeding without SCM context")
	}
	return target
}

// extractErrorDetail returns the most user-readable message from an error.
// For snyk_errors.Error the Detail field contains the full explanation;
// Error() only returns the Title (e.g. "Unspecified Error").
func extractErrorDetail(err error) string {
	var snykErr snyk_errors.Error
	if stderrors.As(err, &snykErr) && snykErr.Detail != "" {
		return snykErr.Detail
	}
	return err.Error()
}

func mapToRawDepGraphWithMeta(result *ecosystems.SCAResult, target []byte) (*RawDepGraphWithMeta, error) {
	if result.Error != nil {
		return nil, fmt.Errorf("failed to resolve depgraph for %s: %w",
			result.ProjectDescriptor.GetTargetFile(), result.Error)
	}

	payload, err := json.Marshal(result.DepGraph)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal depgraph: %w", err)
	}

	return &RawDepGraphWithMeta{
		Payload:              payload,
		NormalisedTargetFile: result.ResolverMetadata.NormalisedTargetFile,
		TargetFileFromPlugin: result.ProjectDescriptor.Identity.TargetFile,
		Target:               target,
	}, nil
}
