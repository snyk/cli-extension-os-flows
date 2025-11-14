package transform_test

import (
	"github.com/snyk/cli-extension-os-flows/internal/commands/ostest"
	"github.com/snyk/cli-extension-os-flows/internal/remediation"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	"github.com/snyk/cli-extension-os-flows/internal/errors"
	"github.com/snyk/cli-extension-os-flows/internal/legacy/transform"
	gafclientmocks "github.com/snyk/go-application-framework/pkg/apiclients/mocks"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/utils"
	"github.com/stretchr/testify/require"
)

func TestRemediation(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	findings := loadFindings(t, "testdata/remediation-findings.json")

	mockTestResult := gafclientmocks.NewMockTestResult(ctrl)
	mockTestSubject := testapi.TestSubject{}
	err := mockTestSubject.FromDepGraphSubject(testapi.DepGraphSubject{})
	require.NoError(t, err)
	mockTestResult.EXPECT().GetTestSubject().Return(mockTestSubject).AnyTimes()

	logger := zerolog.Nop()
	cfg := configuration.New()
	ctx := cmdctx.WithLogger(t.Context(), &logger)
	ctx = cmdctx.WithConfig(ctx, cfg)

	consolidatedFindings, err := ostest.ConsolidateFindings(ctx, findings)
	require.NoError(t, err)
	remFindings, err := remediation.ShimFindingsToRemediationFindings(consolidatedFindings)
	require.NoError(t, err)
	remSummary, err := remediation.FindingsToRemediationSummary(remFindings)
	require.NoError(t, err)

	params := transform.SnykSchemaToLegacyParams{
		Findings:           findings,
		PackageManager:     "npm",
		Logger:             utils.Ptr(logger),
		TestResult:         mockTestResult,
		ErrFactory:         errors.NewErrorFactory(&logger),
		TargetDir:          t.TempDir(),
		RemediationSummary: remSummary,
	}
	result, err := transform.ConvertSnykSchemaFindingsToLegacy(ctx, &params)

	require.NoError(t, err)
	require.NotNil(t, result.Remediation)
	require.Len(t, result.Remediation.Unresolved, 2)
}
