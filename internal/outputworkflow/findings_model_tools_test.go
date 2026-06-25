//nolint:testpackage // to be able to test unexported functions
package outputworkflow

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"
	pkgMocks "github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/presenters"
)

func getUnifiedProjectResultsSkeleton(t *testing.T, counts ...int) []*presenters.UnifiedProjectResult {
	t.Helper()
	results := make([]*presenters.UnifiedProjectResult, 0, len(counts))
	for _, count := range counts {
		summary := &json_schemas.TestSummary{
			Results: []json_schemas.TestSummaryResult{},
		}
		if count > 0 {
			summary.Results = append(summary.Results, json_schemas.TestSummaryResult{Total: count})
		}
		results = append(results, &presenters.UnifiedProjectResult{
			Summary: summary,
		})
	}
	return results
}

func Test_getTotalNumberOfUnifiedFindings(t *testing.T) {
	t.Run("nil results", func(t *testing.T) {
		assert.Equal(t, 0, getTotalNumberOfUnifiedFindings(nil))
	})

	t.Run("count multiple results", func(t *testing.T) {
		projectResults := getUnifiedProjectResultsSkeleton(t, 2, 6)

		// method under test
		actualCount := getTotalNumberOfUnifiedFindings(projectResults)
		assert.Equal(t, 8, actualCount)
	})
}

func Test_getUnifiedProjectResults_AssetLinkPropagates(t *testing.T) {
	logger := zerolog.Nop()

	mkData := func(t *testing.T, contentType string, v any) workflow.Data {
		t.Helper()
		b, err := json.Marshal(v)
		require.NoError(t, err)
		return workflow.NewData(workflow.NewTypeIdentifier(workflow.NewWorkflowIdentifier("test"), "x"), contentType, b)
	}

	findings := []testapi.FindingData{{Attributes: &testapi.FindingAttributes{Title: "x"}}}
	const assetURL = "app.snyk.io/inventory/b6b8bbf8-5cbf-40a2-8991-784fe2a6c8a1"
	summary := presenters.SummaryPayload{
		Summary:   &json_schemas.TestSummary{Type: "open-source"},
		AssetLink: assetURL,
	}

	input := []workflow.Data{
		mkData(t, LocalUnifiedFindingModel, findings),
		mkData(t, LocalUnifiedSummaryModel, summary),
	}

	results, remaining := getUnifiedProjectResults(input, &logger)
	require.Len(t, results, 1)
	assert.Empty(t, remaining)
	assert.Equal(t, assetURL, results[0].AssetLink)
}

func Test_getWritersToUse(t *testing.T) {
	t.Run("default writer only", func(t *testing.T) {
		config := configuration.NewWithOpts()
		buffer := &bytes.Buffer{}

		mockCtl := gomock.NewController(t)
		output := NewMockOutputDestination(mockCtl)
		output.EXPECT().GetWriter().AnyTimes().Return(buffer)

		writerMap := getWritersToUse(config, output)
		assert.Equal(t, 1, len(writerMap))
	})

	t.Run("default writer + configured file writer", func(t *testing.T) {
		newKey := "somethingNewKey"
		buffer := &bytes.Buffer{}
		config := configuration.NewWithOpts()
		config.Set(OutputConfigKeyJSONFile, t.TempDir()+"/test.json")
		config.Set(newKey, t.TempDir()+"/test.new")

		config.Set(OutputConfigKeyFileWriters, []FileWriter{
			{
				OutputConfigKeyJSONFile,
				"application/json",
				[]string{},
				true,
			},
			{
				newKey,
				"application/json",
				[]string{},
				true,
			},
		})

		mockCtl := gomock.NewController(t)
		output := NewMockOutputDestination(mockCtl)
		output.EXPECT().GetWriter().AnyTimes().Return(buffer)

		writerMap := getWritersToUse(config, output)
		assert.Equal(t, 3, len(writerMap))
	})
}

func Test_useRendererWithUnifiedModel(t *testing.T) {
	logger := zerolog.Nop()
	config := configuration.NewWithOpts()
	mockCtl := gomock.NewController(t)
	engine := workflow.NewWorkFlowEngine(config)
	ctx := pkgMocks.NewMockInvocationContext(mockCtl)
	ctx.EXPECT().GetEngine().Return(engine).AnyTimes()
	ctx.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
	ctx.EXPECT().GetConfiguration().Return(config).AnyTimes()
	ctx.EXPECT().GetRuntimeInfo().Return(runtimeinfo.New()).AnyTimes()

	t.Run("render non empty input", func(t *testing.T) {
		buffer := &bytes.Buffer{}
		writer := &WriterEntry{
			writer:          &newLineCloser{writer: buffer},
			mimeType:        DefaultMimeType,
			templates:       presenters.DefaultTemplateFiles,
			renderEmptyData: true,
		}
		projectResults := getUnifiedProjectResultsSkeleton(t, 2)
		useRendererWithUnifiedModel("", writer, projectResults, ctx)
		assert.NotEmpty(t, buffer)
	})

	t.Run("render empty input", func(t *testing.T) {
		buffer := &bytes.Buffer{}
		writer := &WriterEntry{
			writer:          &newLineCloser{writer: buffer},
			mimeType:        DefaultMimeType,
			templates:       presenters.DefaultTemplateFiles,
			renderEmptyData: true,
		}
		projectResults := getUnifiedProjectResultsSkeleton(t, 0)
		useRendererWithUnifiedModel("", writer, projectResults, ctx)
		assert.NotEmpty(t, buffer)
	})

	t.Run("don't render empty input", func(t *testing.T) {
		buffer := &bytes.Buffer{}
		writer := &WriterEntry{
			writer:          &newLineCloser{writer: buffer},
			mimeType:        DefaultMimeType,
			templates:       presenters.DefaultTemplateFiles,
			renderEmptyData: false,
		}
		projectResults := getUnifiedProjectResultsSkeleton(t, 0)
		useRendererWithUnifiedModel("", writer, projectResults, ctx)
		assert.Empty(t, buffer)
	})
}
