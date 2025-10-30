package service_test

import (
	"net/url"
	"testing"

	service "github.com/snyk/cli-extension-os-flows/internal/common"

	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOutputConversion_WhenAllFieldsArePresent(t *testing.T) {
	data := workflow.NewData(mustBeURL(t, "https://abc.com/def"), "application/json", []byte("dep graph JSON bytes"))
	data.SetMetaData(service.NormalisedTargetFileKey, "some normalised target file")
	data.SetMetaData(service.TargetFileFromPluginKey, "some target file from plugin")
	data.SetMetaData(service.TargetKey, `target JSON bytes`)

	depGraph, err := service.WorkflowOutputToRawDepGraphWithMeta(data)

	require.NoError(t, err)
	assert.Equal(t, "dep graph JSON bytes", string(depGraph.Payload))
	assert.Equal(t, "some normalised target file", depGraph.NormalisedTargetFile)
	require.NotNil(t, depGraph.TargetFileFromPlugin)
	assert.Equal(t, "some target file from plugin", *depGraph.TargetFileFromPlugin)
	require.NotNil(t, depGraph.Target)
	assert.Equal(t, "target JSON bytes", string(depGraph.Target))
}

func TestOutputConversion_WhenOptionalFieldsAreMissing(t *testing.T) {
	data := workflow.NewData(mustBeURL(t, "https://abc.com/def"), "application/json", []byte{})
	data.SetMetaData(service.NormalisedTargetFileKey, "")

	depGraph, err := service.WorkflowOutputToRawDepGraphWithMeta(data)

	require.NoError(t, err)
	assert.Nil(t, depGraph.TargetFileFromPlugin)
	assert.Nil(t, depGraph.Target)
}

func mustBeURL(t *testing.T, urlStr string) *url.URL {
	t.Helper()
	u, err := url.Parse(urlStr)
	require.NoError(t, err)
	return u
}
