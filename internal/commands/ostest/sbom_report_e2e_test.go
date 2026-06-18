//nolint:testpackage // Uses unexported executeFlow and validateSbomReport; keeping in-package keeps the test scope minimal.
package ostest

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/snyk/go-application-framework/pkg/apiclients/fileupload"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	"github.com/snyk/cli-extension-os-flows/internal/common"
	"github.com/snyk/cli-extension-os-flows/internal/constants"
	"github.com/snyk/cli-extension-os-flows/internal/util"
	"github.com/snyk/cli-extension-os-flows/pkg/flags"
)

// Test_SbomReport_E2E exercises the full `snyk sbom test --report` happy path:
// from flag parsing and FlowConfig resolution, through validation in RouteToFlow,
// through executeFlow into common.RunSbomFlow, all the way down to the
// TestConfiguration sent to the test API. It validates the wiring established
// across phases 1-4 of OSF-427 in one regression net.
func Test_SbomReport_E2E(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx, cfg := setupExecuteFlowCtx(t, ctrl)

	cfg.Set(flags.FlagSBOM, "./testdata/bom.json")
	cfg.Set(flags.FlagReport, true)
	cfg.Set(flags.FlagFile, "bom.json")
	cfg.Set(flags.FlagAssetName, "my-app")
	cfg.Set(constants.FeatureFlagDflySbomMonitor, true)
	cfg.Set(flags.FlagRiskScoreThreshold, -1)

	flowCfg, err := ParseFlowConfig(cfg)
	require.NoError(t, err)

	// Validation must accept the configuration once all three of --sbom,
	// --report, --file, --asset-name (and the FF) are present.
	errFactory := cmdctx.ErrorFactory(ctx)
	require.NoError(t, validateSbomReport(flowCfg, errFactory))

	orgUUID := uuid.New()
	ffc := fileupload.NewFakeClient()
	mockTestClient, getCapturedConfig := setupExecuteFlowCapturingTestClient(ctrl)

	clients := common.FlowClients{
		TestClient:       mockTestClient,
		FileUploadClient: ffc,
	}

	// Compute publishReport from FlowConfig exactly as OSWorkflow does.
	var publishReport *bool
	if flowCfg.Report && flowCfg.FFDflySbomMonitor {
		publishReport = util.Ptr(true)
	}

	_, _, err = executeFlow(
		ctx,
		SbomFlow,
		clients,
		orgUUID,
		"./testdata",
		"",
		flowCfg.SBOM,
		nil,
		false,
		publishReport,
	)
	require.NoError(t, err)

	capturedConfig := getCapturedConfig()
	require.NotNil(t, capturedConfig)

	require.NotNil(t, capturedConfig.PublishReport, "PublishReport must be true for --report runs")
	assert.True(t, *capturedConfig.PublishReport)

	// NOTE: until go-application-framework exposes TestConfiguration.AssetName,
	// --asset-name is forwarded into TargetName as a temporary alias. See OSF-427.
	require.NotNil(t, capturedConfig.TargetName, "--asset-name must propagate into TestConfiguration")
	assert.Equal(t, "my-app", *capturedConfig.TargetName)

	assert.Equal(t, 1, ffc.GetUploadCount(), "only the SBOM document should be uploaded")
}
