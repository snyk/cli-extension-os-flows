package output_workflow

import "github.com/snyk/cli-extension-os-flows/internal/presenters"

const (
	OUTPUT_CONFIG_KEY_JSON         = "json"
	OUTPUT_CONFIG_KEY_JSON_FILE    = "json-file-output"
	OUTPUT_CONFIG_TEMPLATE_FILE    = "internal_template_file"
	OUTPUT_CONFIG_KEY_FILE_WRITERS = "internal_output_file_writers"
	DEFAULT_WRITER                 = "default"
	DEFAULT_MIME_TYPE              = presenters.DefaultMimeType
)

const (
	TEST_SUMMARY                = "application/json; schema=test-summary"
	LOCAL_UNIFIED_FINDING_MODEL = "application/json; schema=local-unified-finding"
	LOCAL_UNIFIED_SUMMARY_MODEL = "application/json; schema=local-unified-summary"
)
