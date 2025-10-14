//nolint:revive // Interferes with inline types from testapi.
package ostest_test

import (
	"context"
	"regexp"
	"testing"
	"time"

	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	gafclientmocks "github.com/snyk/go-application-framework/pkg/apiclients/mocks"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	gafmocks "github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-os-flows/internal/bundlestore"
	"github.com/snyk/cli-extension-os-flows/internal/commands/ostest"
	"github.com/snyk/cli-extension-os-flows/internal/errors"
	"github.com/snyk/cli-extension-os-flows/internal/mocks"
	"github.com/snyk/cli-extension-os-flows/internal/outputworkflow"
)

//go:generate go run github.com/golang/mock/mockgen -package=mocks -destination=../../mocks/mock_bundlestore_client.go github.com/snyk/cli-extension-os-flows/internal/bundlestore Client

// pathRgxp is used for replacing the "path" in the output for snapshot consistency.
var pathRgxp = regexp.MustCompile(`\s*,?"path"\s*:\s*"[^"]*",?`)

var nopLogger = zerolog.Nop()

func Test_RunSbomReachabilityFlow_JSON(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	ef := errors.NewErrorFactory(&nopLogger)
	mockIctx, mockTestClient, mockBsClient, orgID, sbomPath, sourceCodePath := setupTest(ctx, t, ctrl, true)

	// This should now succeed with proper finding data
	result, err := ostest.RunSbomReachabilityFlow(ctx, mockIctx, mockTestClient, ef, &nopLogger, sbomPath, sourceCodePath, mockBsClient, orgID, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	require.Len(t, result, 2)                                                                // Should return legacy data + summary data
	require.Contains(t, result[0].GetContentType(), "application/json")                      // legacy data
	require.Contains(t, result[1].GetContentType(), "application/json; schema=test-summary") // summary data

	legacyJSON, ok := result[0].GetPayload().([]byte)
	require.True(t, ok)
	legacySummary, ok := result[1].GetPayload().([]byte)
	require.True(t, ok)
	snaps.MatchJSON(t, pathRgxp.ReplaceAll(legacyJSON, nil))
	snaps.MatchJSON(t, pathRgxp.ReplaceAll(legacySummary, nil))
}

func Test_RunSbomReachabilityFlow_HumanReadable(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	ef := errors.NewErrorFactory(&nopLogger)
	mockIctx, mockTestClient, mockBsClient, orgID, sbomPath, sourceCodePath := setupTest(ctx, t, ctrl, false)

	// This should now succeed with proper finding data
	result, err := ostest.RunSbomReachabilityFlow(ctx, mockIctx, mockTestClient, ef, &nopLogger, sbomPath, sourceCodePath, mockBsClient, orgID, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	require.Len(t, result, 1)
	require.Contains(t, result[0].GetContentType(), "application/json; schema=test-summary")

	legacySummary, ok := result[0].GetPayload().([]byte)
	require.True(t, ok)
	snaps.MatchJSON(t, pathRgxp.ReplaceAll(legacySummary, nil))
}

//nolint:gocritic // Not important for tests.
func setupTest(ctx context.Context, t *testing.T, ctrl *gomock.Controller, jsonOutput bool) (
	workflow.InvocationContext,
	testapi.TestClient,
	bundlestore.Client,
	string,
	string,
	string,
) {
	t.Helper()
	sbomPath := "./testdata/bom.json"
	sourceCodePath := "./testdata/test_dir"
	orgID := "test-org-id"
	orgSlug := "test-org-slug"

	vulnTime, err := time.Parse(time.RFC3339, "2025-07-28T17:11:43+03:00")
	require.NoError(t, err)

	// Create finding data
	findingID := uuid.New()
	vulnID := "snyk-vuln-123"

	ecosystem := testapi.SnykvulndbPackageEcosystem{}
	err = ecosystem.FromSnykvulndbBuildPackageEcosystem(testapi.SnykvulndbBuildPackageEcosystem{
		Language:       "js",
		PackageManager: "npm",
		Type:           testapi.Build,
	})
	require.NoError(t, err)
	// Create a mock Problem
	var problem testapi.Problem
	err = problem.FromSnykVulnProblem(testapi.SnykVulnProblem{
		Id:             vulnID,
		PackageName:    "foo",
		PackageVersion: "0.0.0",
		IsMalicious:    true,
		Ecosystem:      ecosystem,
		CreatedAt:      vulnTime,
		DisclosedAt:    vulnTime,
		ModifiedAt:     vulnTime,
		PublishedAt:    vulnTime,
	})
	require.NoError(t, err)

	// Create a mock Location (SourceFile)
	var location testapi.FindingLocation
	err = location.FromPackageLocation(testapi.PackageLocation{
		Package: testapi.Package{
			Name:    "foo",
			Version: "0.0.0",
		},
		Type: testapi.PackageLocationTypePackage,
	})
	require.NoError(t, err)

	// Create mock evidence
	reachEv := testapi.Evidence{}
	err = reachEv.FromReachabilityEvidence(testapi.ReachabilityEvidence{
		Reachability: testapi.ReachabilityTypeFunction,
	})
	require.NoError(t, err)

	depPathEv := testapi.Evidence{}
	err = depPathEv.FromDependencyPathEvidence(testapi.DependencyPathEvidence{
		Path: []testapi.Package{
			{
				Name:    "root",
				Version: "1.0.0",
			},
			{
				Name:    "foo",
				Version: "0.0.0",
			},
		},
		Source: testapi.DependencyPath,
	})
	require.NoError(t, err)

	// Create mock FindingAttributes
	findingAttrs := testapi.FindingAttributes{
		CauseOfFailure: false,
		Description:    "Test vulnerability description",
		Evidence:       []testapi.Evidence{reachEv, depPathEv},
		FindingType:    testapi.FindingTypeSca,
		Key:            "TEST-FINDING-KEY",
		Locations:      []testapi.FindingLocation{location},
		Problems:       []testapi.Problem{problem},
		Rating:         testapi.Rating{Severity: testapi.SeverityHigh},
		Risk:           testapi.Risk{RiskScore: &testapi.RiskScore{Value: uint16(80)}},
		Title:          "Test High Severity Finding",
	}

	act := testapi.Action{}
	act.FromUpgradePackageAction(testapi.UpgradePackageAction{
		Type:        testapi.UpgradePackage,
		PackageName: "foo",
		UpgradePaths: []testapi.UpgradePath{
			{
				DependencyPath: []testapi.Package{
					{
						Name:    "root",
						Version: "1.0.0",
					},
					{
						Name:    "foo",
						Version: "1.0.0",
					},
				},
				IsDrop: false,
			},
		},
	})

	// Create mock FindingData
	findingDataType := testapi.Findings
	findingData := testapi.FindingData{
		Attributes: &findingAttrs,
		Id:         &findingID,
		Type:       &findingDataType,
		Relationships: &struct {
			Asset *struct {
				Data *struct {
					Id   uuid.UUID "json:\"id\""
					Type string    "json:\"type\""
				} "json:\"data,omitempty\""
				Links testapi.IoSnykApiCommonRelatedLink "json:\"links\""
				Meta  *testapi.IoSnykApiCommonMeta       "json:\"meta,omitempty\""
			} "json:\"asset,omitempty\""
			Fix *struct {
				Data *struct {
					Attributes *testapi.FixAttributes "json:\"attributes,omitempty\""
					Id         uuid.UUID              "json:\"id\""
					Type       string                 "json:\"type\""
				} "json:\"data,omitempty\""
			} "json:\"fix,omitempty\""
			Org *struct {
				Data *struct {
					Id   uuid.UUID "json:\"id\""
					Type string    "json:\"type\""
				} "json:\"data,omitempty\""
			} "json:\"org,omitempty\""
			Policy *struct {
				Data *struct {
					Id   uuid.UUID "json:\"id\""
					Type string    "json:\"type\""
				} "json:\"data,omitempty\""
				Links testapi.IoSnykApiCommonRelatedLink "json:\"links\""
				Meta  *testapi.IoSnykApiCommonMeta       "json:\"meta,omitempty\""
			} "json:\"policy,omitempty\""
			Test *struct {
				Data *struct {
					Id   uuid.UUID "json:\"id\""
					Type string    "json:\"type\""
				} "json:\"data,omitempty\""
				Links testapi.IoSnykApiCommonRelatedLink "json:\"links\""
				Meta  *testapi.IoSnykApiCommonMeta       "json:\"meta,omitempty\""
			} "json:\"test,omitempty\""
		}{
			Fix: &struct {
				Data *struct {
					Attributes *testapi.FixAttributes "json:\"attributes,omitempty\""
					Id         uuid.UUID              "json:\"id\""
					Type       string                 "json:\"type\""
				} "json:\"data,omitempty\""
			}{
				Data: &struct {
					Attributes *testapi.FixAttributes "json:\"attributes,omitempty\""
					Id         uuid.UUID              "json:\"id\""
					Type       string                 "json:\"type\""
				}{
					Attributes: &testapi.FixAttributes{
						Outcome: testapi.FullyResolved,
						Actions: &act,
					},
				},
			},
		},
	}

	// Create test summary data
	summary := &testapi.FindingSummary{
		Count: 1,
		CountBy: &map[string]map[string]uint32{
			"severity": {
				"high": 1,
			},
		},
	}

	// Create test subject
	var testSubject testapi.TestSubject
	err = testSubject.FromSbomReachabilitySubject(testapi.SbomReachabilitySubject{
		Type:         testapi.SbomReachability,
		CodeBundleId: "test-source-hash",
		SbomBundleId: "test-sbom-hash",
		Locator: testapi.LocalPathLocator{
			Paths: []string{
				sbomPath,
				sourceCodePath,
			},
			Type: testapi.LocalPath,
		},
	})

	require.NoError(t, err)

	// Mock TestResult with comprehensive data
	mockTestResult := gafclientmocks.NewMockTestResult(ctrl)
	mockTestResult.EXPECT().GetExecutionState().Return(testapi.Finished).Times(1)
	mockTestResult.EXPECT().Findings(gomock.Any()).Return([]testapi.FindingData{findingData}, true, nil).Times(1)
	mockTestResult.EXPECT().GetTestSubject().Return(testSubject).AnyTimes()
	mockTestResult.EXPECT().GetEffectiveSummary().Return(summary).AnyTimes()
	mockTestResult.EXPECT().GetRawSummary().Return(summary).AnyTimes()

	// Mock TestHandle
	mockTestHandle := gafclientmocks.NewMockTestHandle(ctrl)
	mockTestHandle.EXPECT().Wait(gomock.Any()).Return(nil).Times(1)
	mockTestHandle.EXPECT().Result().Return(mockTestResult).Times(1)

	// Mock TestClient
	mockTestClient := gafclientmocks.NewMockTestClient(ctrl)
	mockTestClient.EXPECT().StartTest(gomock.Any(), gomock.Any()).Return(mockTestHandle, nil).Times(1)

	// Mock BundleStore Client
	mockBsClient := mocks.NewMockClient(ctrl)
	mockBsClient.EXPECT().UploadSBOM(ctx, sbomPath).Return("test-sbom-hash", nil).Times(1)
	mockBsClient.EXPECT().UploadSourceCode(ctx, sourceCodePath).Return("test-source-hash", nil).Times(1)

	// Mock Invocation Context
	mockConfig := configuration.New()
	mockConfig.Set(outputworkflow.OutputConfigKeyJSON, jsonOutput)
	mockConfig.Set(configuration.ORGANIZATION_SLUG, orgSlug)
	mockIctx := gafmocks.NewMockInvocationContext(ctrl)
	mockIctx.EXPECT().GetConfiguration().Return(mockConfig).AnyTimes()
	mockIctx.EXPECT().GetEnhancedLogger().Return(&nopLogger).AnyTimes()
	mockIctx.EXPECT().GetRuntimeInfo().Return(runtimeinfo.New()).AnyTimes()

	return mockIctx, mockTestClient, mockBsClient, orgID, sbomPath, sourceCodePath
}
