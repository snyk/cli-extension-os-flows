package osmonitor_test

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/commands/osmonitor"
	"github.com/snyk/cli-extension-os-flows/pkg/flags"
)

// Test_OSWorkflow_WithSBOM_ReturnsSbomMonitorRemovedError ensures that the
// previously-supported `snyk monitor --sbom=...` dragonfly entrypoint surfaces
// a clear deprecation error pointing users to the new
// `snyk sbom test --report` command (per OSF-427).
func Test_OSWorkflow_WithSBOM_ReturnsSbomMonitorRemovedError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := createMockEngine(ctrl)
	mockIctx := createMockInvocationCtxWithURL(t, ctrl, mockEngine)
	cfg := mockIctx.GetConfiguration()
	cfg.Set(flags.FlagSBOM, "testdata/bom.json")
	cfg.Set(configuration.INPUT_DIRECTORY, t.TempDir())

	_, err := osmonitor.OSWorkflow(mockIctx, []workflow.Data{})

	require.Error(t, err)
	assert.ErrorContains(t, err, "sbom test --report")
	// Must NOT route through the previous dragonfly SBOM monitor path.
	assert.NotContains(t, err.Error(), "failed to upload SBOM")
}
