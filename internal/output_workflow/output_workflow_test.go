package output_workflow

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/cli-extension-os-flows/internal/presenters"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/content_type"
	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func Test_Output_InitOutputWorkflow(t *testing.T) {
	config := configuration.New()
	engine := workflow.NewWorkFlowEngine(config)

	err := InitOutputWorkflow(engine)
	assert.Nil(t, err)

	json := config.GetBool("json")
	assert.Equal(t, false, json)

	jsonFileOutput := config.GetString("json-file-output")
	assert.Equal(t, "", jsonFileOutput)
}

func Test_Output_outputWorkflowEntryPoint(t *testing.T) {
	logger := zerolog.Nop()
	config := configuration.NewInMemory()
	writer := new(bytes.Buffer)

	// setup mocks
	ctrl := gomock.NewController(t)
	invocationContextMock := mocks.NewMockInvocationContext(ctrl)
	outputDestination := NewMockOutputDestination(ctrl)

	// invocation context mocks
	invocationContextMock.EXPECT().GetConfiguration().Return(config).AnyTimes()
	invocationContextMock.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
	invocationContextMock.EXPECT().GetRuntimeInfo().Return(runtimeinfo.New(runtimeinfo.WithName("Random Application Name"), runtimeinfo.WithVersion("1.0.0"))).AnyTimes()

	outputDestination.EXPECT().GetWriter().Return(writer).AnyTimes()

	payload := `
	{
		"schemaVersion": "1.2.0",
		"pkgManager": {
			"name": "npm"
		},
		"pkgs": [
			{
				"id": "goof@1.0.1",
				"info": {
					"name": "goof",
					"version": "1.0.1"
				}
			}
		],
		"graph": {
			"rootNodeId": "root-node",
			"nodes": [
				{
					"nodeId": "root-node",
					"pkgId": "goof@1.0.1",
					"deps": [
						{
							"nodeId": "adm-zip@0.4.7"
						},
						{
							"nodeId": "body-parser@1.9.0"
						}
					]
				}
			]
		}
	}`

	t.Run("should not output to stdout for application/json", func(t *testing.T) {
		workflowIdentifier := workflow.NewTypeIdentifier(WORKFLOWID_OUTPUT_WORKFLOW, "output")
		data := workflow.NewData(workflowIdentifier, "application/json", []byte(payload))

		// mock assertions
		outputDestination.EXPECT().Println(gomock.Any()).Times(0)

		// execute
		output, err := OutputWorkflowEntryPoint(invocationContextMock, []workflow.Data{data}, outputDestination)

		// assert
		assert.Nil(t, err)
		assert.Equal(t, []workflow.Data{}, output)
	})

	t.Run("should output to stdout by default for text/plain", func(t *testing.T) {
		workflowIdentifier := workflow.NewTypeIdentifier(WORKFLOWID_OUTPUT_WORKFLOW, "output")
		data := workflow.NewData(workflowIdentifier, "text/plain", []byte(payload))

		// mock assertions
		outputDestination.EXPECT().Println(payload).Return(0, nil).Times(1)

		// execute
		output, err := OutputWorkflowEntryPoint(invocationContextMock, []workflow.Data{data}, outputDestination)

		// assert
		assert.Nil(t, err)
		assert.Equal(t, []workflow.Data{}, output)
	})

	t.Run("should print unsupported mimeTypes that are string convertible", func(t *testing.T) {
		workflowIdentifier := workflow.NewTypeIdentifier(WORKFLOWID_OUTPUT_WORKFLOW, "output")
		data := workflow.NewData(workflowIdentifier, "hammer/head", payload)

		// mock assertions
		outputDestination.EXPECT().Println(payload).Return(0, nil).Times(1)

		// execute
		output, err := OutputWorkflowEntryPoint(invocationContextMock, []workflow.Data{data}, outputDestination)

		// assert
		assert.Nil(t, err)
		assert.Equal(t, []workflow.Data{}, output)
	})

	t.Run("should reject unsupported mimeTypes", func(t *testing.T) {
		workflowIdentifier := workflow.NewTypeIdentifier(WORKFLOWID_OUTPUT_WORKFLOW, "output")
		data := workflow.NewData(workflowIdentifier, "hammer/head", workflowIdentifier) // re-using workflowIdentifier as data to have some non string data

		// execute
		output, err := OutputWorkflowEntryPoint(invocationContextMock, []workflow.Data{data}, outputDestination)

		// assert
		assert.Equal(t, []workflow.Data{}, output)
		assert.Equal(t, "unsupported output type: hammer/head", err.Error())
	})

	t.Run("should not output anything for test summary mimeType", func(t *testing.T) {
		workflowIdentifier := workflow.NewTypeIdentifier(WORKFLOWID_OUTPUT_WORKFLOW, "output")
		data := workflow.NewData(workflowIdentifier, content_type.TEST_SUMMARY, []byte(payload))

		// mock assertions
		outputDestination.EXPECT().Println(payload).Return(0, nil).Times(0)

		// execute
		output, err := OutputWorkflowEntryPoint(invocationContextMock, []workflow.Data{data}, outputDestination)

		// assert
		assert.Nil(t, err)
		assert.Equal(t, 1, len(output))
	})

	t.Run("should not output anything for versioned test summary mimeType", func(t *testing.T) {
		versionedTestSummaryContentType := content_type.TEST_SUMMARY + "; version=2024-04-10"
		workflowIdentifier := workflow.NewTypeIdentifier(WORKFLOWID_OUTPUT_WORKFLOW, "output")
		data := workflow.NewData(workflowIdentifier, versionedTestSummaryContentType, []byte(payload))

		// mock assertions
		outputDestination.EXPECT().Println(payload).Return(0, nil).Times(0)

		// execute
		output, err := OutputWorkflowEntryPoint(invocationContextMock, []workflow.Data{data}, outputDestination)

		// assert
		assert.Nil(t, err)
		assert.Equal(t, 1, len(output))
	})

	t.Run("should reject test summary mimeType and display known mimeType", func(t *testing.T) {
		workflowIdentifier := workflow.NewTypeIdentifier(WORKFLOWID_OUTPUT_WORKFLOW, "output")
		testSummaryData := workflow.NewData(workflowIdentifier, content_type.TEST_SUMMARY, []byte(payload))
		textData := workflow.NewData(workflowIdentifier, "text/plain", []byte(payload))

		// mock assertions
		outputDestination.EXPECT().Println(payload).Return(0, nil).Times(1)

		// execute
		output, err := OutputWorkflowEntryPoint(invocationContextMock, []workflow.Data{testSummaryData, textData}, outputDestination)

		// assert
		assert.Nil(t, err)
		assert.Equal(t, 1, len(output))
	})
}

func TestUnifiedFindingsHandling_renderFilesAndUI(t *testing.T) {
	logger := zerolog.Nop()
	config := configuration.NewWithOpts()

	fileWriters := []FileWriter{
		{
			NameConfigKey:     OUTPUT_CONFIG_KEY_JSON_FILE,
			MimeType:          "application/json",
			TemplateFiles:     []string{"testdata/custom_template.tmpl"},
			WriteEmptyContent: false,
		},
	}
	config.Set(OUTPUT_CONFIG_KEY_FILE_WRITERS, fileWriters)

	// setup mocks
	ctrl := gomock.NewController(t)
	invocationContextMock := mocks.NewMockInvocationContext(ctrl)
	outputDestination := NewMockOutputDestination(ctrl)

	// invocation context mocks
	invocationContextMock.EXPECT().GetConfiguration().Return(config).AnyTimes()
	invocationContextMock.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
	invocationContextMock.EXPECT().GetRuntimeInfo().Return(runtimeinfo.New(runtimeinfo.WithName("snyk-cli"), runtimeinfo.WithVersion("1.2.3"))).AnyTimes()

	byteBuffer := &bytes.Buffer{}
	outputDestination.EXPECT().GetWriter().Return(byteBuffer).AnyTimes()

	expectedJsonFile := filepath.Join(t.TempDir(), "TestLocalFindingsHandling.json")
	config.Set(OUTPUT_CONFIG_KEY_JSON_FILE, expectedJsonFile)
	config.Set(configuration.MAX_THREADS, 10)

	// Create mock unified findings data
	findings := []testapi.FindingData{
		{Attributes: &testapi.FindingAttributes{Title: "My Finding"}},
	}
	findingsBytes, err := json.Marshal(findings)
	assert.NoError(t, err)

	summaryPayload := presenters.SummaryPayload{
		Summary: &json_schemas.TestSummary{
			Type: "sast",
			Path: "/my/project",
			Results: []json_schemas.TestSummaryResult{
				{Severity: "high", Total: 1, Open: 1},
			},
		},
		DependencyCount:   10,
		PackageManager:    "npm",
		ProjectName:       "test-project",
		DisplayTargetFile: "package.json",
		UniqueCount:       1,
	}
	summaryBytes, err := json.Marshal(summaryPayload)
	assert.NoError(t, err)

	unifiedFindingData := workflow.NewData(workflow.NewTypeIdentifier(workflow.NewWorkflowIdentifier("test"), "unified-finding"), LOCAL_UNIFIED_FINDING_MODEL, findingsBytes)
	unifiedSummaryData := workflow.NewData(workflow.NewTypeIdentifier(workflow.NewWorkflowIdentifier("test"), "unified-summary"), LOCAL_UNIFIED_SUMMARY_MODEL, summaryBytes)

	randomData1 := workflow.NewData(workflow.NewTypeIdentifier(workflow.NewWorkflowIdentifier("test"), "random"), "application/json", []byte{})
	randomData2 := workflow.NewData(workflow.NewTypeIdentifier(workflow.NewWorkflowIdentifier("test"), "random"), "plain", []byte{})
	input := []workflow.Data{randomData1, unifiedFindingData, unifiedSummaryData, randomData2}

	// invoking method under test
	actualRemainingData, err := HandleContentTypeUnifiedModel(input, invocationContextMock, outputDestination)
	assert.NoError(t, err)
	assert.NotNil(t, actualRemainingData)

	expectedRemainingData := []workflow.Data{randomData1, randomData2}
	assert.Equal(t, expectedRemainingData, actualRemainingData)

	dataFromJsonFile, err := os.ReadFile(expectedJsonFile)
	assert.NoError(t, err, "reading json file")
	assert.NotEmpty(t, dataFromJsonFile, "json file should not be empty")

	dataFromBuffer := byteBuffer.Bytes()
	assert.NotEmpty(t, dataFromBuffer)
}
