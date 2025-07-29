package outputworkflow

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/content_type"
	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"

	"github.com/snyk/cli-extension-os-flows/internal/presenters"
)

var workflowIDOutputWorkflow workflow.Identifier = workflow.NewWorkflowIdentifier("osflows_output")

// InitOutputWorkflow initializes the output workflow.
// The output workflow is responsible for handling the output destination of workflow data.
// As part of the localworkflows package, it is registered via the localworkflows.Init method.
func InitOutputWorkflow(engine workflow.Engine) error {
	outputConfig := pflag.NewFlagSet("osflows_output", pflag.ContinueOnError)
	outputConfig.Bool(configuration.FLAG_INCLUDE_IGNORES, false, "Include ignored findings in the output")
	outputConfig.String(configuration.FLAG_SEVERITY_THRESHOLD, "low", "Severity threshold for findings to be included in the output")
	outputConfig.Bool(OutputConfigKeyJSON, false, "Output in JSON format.")
	outputConfig.String(OutputConfigKeyJSONFile, "", "Write JSON output to a file.")

	entry, err := engine.Register(workflowIDOutputWorkflow, workflow.ConfigurationOptionsFromFlagset(outputConfig), outputWorkflowEntryPointImpl)
	entry.SetVisibility(false)

	if err != nil {
		return fmt.Errorf("failed to register output workflow: %w", err)
	}
	return nil
}

func filterSummaryOutput(config configuration.Configuration, input workflow.Data, logger *zerolog.Logger) (workflow.Data, error) {
	// Parse the summary data
	summary := json_schemas.NewTestSummary("", "")
	payload, ok := input.GetPayload().([]byte)
	if !ok {
		return nil, fmt.Errorf("invalid payload type: %T", input.GetPayload())
	}
	err := json.Unmarshal(payload, &summary)
	if err != nil {
		return input, fmt.Errorf("failed to unmarshal summary payload: %w", err)
	}

	minSeverity := config.GetString(configuration.FLAG_SEVERITY_THRESHOLD)
	filteredSeverityOrderAsc := presenters.FilterSeverityASC(summary.SeverityOrderAsc, minSeverity)

	// Filter out the results based on the configuration
	var filteredResults []json_schemas.TestSummaryResult

	for _, severity := range filteredSeverityOrderAsc {
		for _, result := range summary.Results {
			if severity == result.Severity {
				filteredResults = append(filteredResults, result)
			}
		}
	}

	summary.Results = filteredResults

	bytes, err := json.Marshal(summary)
	if err != nil {
		return input, fmt.Errorf("failed to marshal summary: %w", err)
	}

	workflowID := workflow.NewTypeIdentifier(workflowIDOutputWorkflow, "FilterTestSummary")
	output := workflow.NewData(
		workflowID,
		content_type.TEST_SUMMARY,
		bytes,
		workflow.WithInputData(input),
		workflow.WithLogger(logger))

	return output, nil
}

// EntryPoint defines the output entry point.
// the entry point is called by the engine when the workflow is invoked.
func EntryPoint(invocation workflow.InvocationContext, input []workflow.Data, outputDestination OutputDestination) ([]workflow.Data, error) {
	output := []workflow.Data{}

	config := invocation.GetConfiguration()
	debugLogger := invocation.GetEnhancedLogger()

	// Handle findings models, if none found, continue with the rest
	input, err := HandleContentTypeUnifiedModel(input, invocation, outputDestination)
	if err != nil {
		return output, err
	}

	for i := range input {
		mimeType := input[i].GetContentType()

		if strings.HasPrefix(mimeType, content_type.TEST_SUMMARY) {
			outputSummary, err := filterSummaryOutput(config, input[i], debugLogger)
			if err != nil {
				debugLogger.Warn().Err(err).Msg("Failed to filter test summary output")
				output = append(output, input[i])
			}
			output = append(output, outputSummary)
			continue
		}

		contentLocation := input[i].GetContentLocation()
		if contentLocation == "" {
			contentLocation = "unknown"
		}

		debugLogger.Printf("Processing '%s' based on '%s' of type '%s'", input[i].GetIdentifier().String(), contentLocation, mimeType)

		if !strings.Contains(mimeType, "json") { // handle text/plain and unknown the same way
			err := handleContentTypeOthers(input, i, mimeType, outputDestination)
			if err != nil {
				return output, err
			}
		}
	}

	return output, nil
}

func handleContentTypeOthers(input []workflow.Data, i int, mimeType string, outputDestination OutputDestination) error {
	// try to convert payload to a string
	var singleDataAsString string
	singleData, typeCastSuccessful := input[i].GetPayload().([]byte)
	if !typeCastSuccessful {
		singleDataAsString, typeCastSuccessful = input[i].GetPayload().(string)
		if !typeCastSuccessful {
			return fmt.Errorf("unsupported output type: %s", mimeType)
		}
	} else {
		singleDataAsString = string(singleData)
	}

	outputDestination.Println(singleDataAsString)
	return nil
}

func outputWorkflowEntryPointImpl(invocation workflow.InvocationContext, input []workflow.Data) (output []workflow.Data, err error) {
	outputDestination := NewOutputDestination()
	return EntryPoint(invocation, input, outputDestination)
}
