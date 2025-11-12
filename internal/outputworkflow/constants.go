package outputworkflow

import "github.com/snyk/cli-extension-os-flows/internal/presenters"

const (
	// OutputConfigKeyJSON is a constant for the JSON output configuration key.
	OutputConfigKeyJSON = "json"
	// OutputConfigKeyJSONFile is a constant for the JSON file output configuration key.
	OutputConfigKeyJSONFile = "json-file-output"
	// OutputConfigTemplateFile is a constant for the template file output configuration key.
	OutputConfigTemplateFile = "internal_template_file"
	// OutputConfigKeyFileWriters is a constant for the file writers output configuration key.
	OutputConfigKeyFileWriters = "internal_output_file_writers"
	// DefaultWriter is a constant for the default writer.
	DefaultWriter = "default"
	// DefaultMimeType is a constant for the default mime type.
	DefaultMimeType = presenters.DefaultMimeType
	// OutputConfigKeyNoOutput is a constant for the no output configuration key that allows switching off outputs.
	OutputConfigKeyNoOutput = "no-output"
)

const (
	// TestSummary is a constant for the test summary content type.
	TestSummary = "application/json; schema=test-summary"
	// LocalUnifiedFindingModel is a constant for the local unified finding model content type.
	LocalUnifiedFindingModel = "application/json; schema=local-unified-finding"
	// LocalUnifiedSummaryModel is a constant for the local unified summary model content type.
	LocalUnifiedSummaryModel = "application/json; schema=local-unified-summary"
)
