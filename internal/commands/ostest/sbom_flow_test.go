//nolint:revive // Interferes with inline types from testapi.
package ostest_test

import (
	"encoding/json"
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
	"github.com/snyk/go-application-framework/pkg/utils/ufm"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-os-flows/internal/bundlestore"
	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	"github.com/snyk/cli-extension-os-flows/internal/commands/ostest"
	"github.com/snyk/cli-extension-os-flows/internal/errors"
	"github.com/snyk/cli-extension-os-flows/internal/mocks"
	"github.com/snyk/cli-extension-os-flows/internal/outputworkflow"
	"github.com/snyk/cli-extension-os-flows/internal/util"
)

//go:generate go run github.com/golang/mock/mockgen -package=mocks -destination=../../mocks/mock_bundlestore_client.go github.com/snyk/cli-extension-os-flows/internal/bundlestore Client

// idRgxp is used for replacing the "id" in the output for snapshot consistency.
var idRgxp = regexp.MustCompile(`\s*,?"id"\s*:\s*"[^"]*"?`)

var nopLogger = zerolog.Nop()

func Test_RunSbomFlow_Reachability_JSON(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ef := errors.NewErrorFactory(&nopLogger)
	mockIctx, mockTestClient, mockBsClient, orgID, sbomPath, sourceCodePath := setupTest(t, ctrl, true, true)
	ctx := t.Context()
	ctx = cmdctx.WithIctx(ctx, mockIctx)
	ctx = cmdctx.WithConfig(ctx, mockIctx.GetConfiguration())
	ctx = cmdctx.WithLogger(ctx, &nopLogger)
	ctx = cmdctx.WithErrorFactory(ctx, ef)
	ctx = cmdctx.WithProgressBar(ctx, &nopProgressBar)

	// This should now succeed with proper finding data
	legacyJSON, outputData, err := ostest.RunSbomFlow(ctx, mockTestClient, sbomPath, sourceCodePath, mockBsClient, orgID, nil, true)
	require.NoError(t, err)

	require.NotNil(t, legacyJSON)
	jsonBytes, err := json.Marshal(legacyJSON)
	require.NoError(t, err)
	snaps.MatchJSON(t, jsonBytes)

	require.NotNil(t, outputData)
	// Output data should contain standard summary and unified model test result
	require.Len(t, outputData, 2)

	require.Contains(t, "application/json; schema=test-summary", outputData[0].GetContentType())
	summary, ok := outputData[0].GetPayload().([]byte)
	require.True(t, ok)
	snaps.MatchJSON(t, summary)

	testResult := ufm.GetTestResultsFromWorkflowData(outputData[1])
	require.Len(t, testResult, 1)
}

func Test_RunSbomFlow_Reachability_HumanReadable(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ef := errors.NewErrorFactory(&nopLogger)
	mockIctx, mockTestClient, mockBsClient, orgID, sbomPath, sourceCodePath := setupTest(t, ctrl, false, true)
	ctx := t.Context()
	ctx = cmdctx.WithIctx(ctx, mockIctx)
	ctx = cmdctx.WithConfig(ctx, mockIctx.GetConfiguration())
	ctx = cmdctx.WithLogger(ctx, &nopLogger)
	ctx = cmdctx.WithErrorFactory(ctx, ef)
	ctx = cmdctx.WithProgressBar(ctx, &nopProgressBar)

	// This should now succeed with proper finding data
	legacyJSON, outputData, err := ostest.RunSbomFlow(ctx, mockTestClient, sbomPath, sourceCodePath, mockBsClient, orgID, nil, true)
	require.NoError(t, err)

	require.Nil(t, legacyJSON)
	require.NotNil(t, outputData)
	// Output data should contain standard summary, unified model test result, local unified findings and local unified summary
	require.Len(t, outputData, 4)

	require.Contains(t, "application/json; schema=test-summary", outputData[0].GetContentType())
	summary, ok := outputData[0].GetPayload().([]byte)
	require.True(t, ok)
	snaps.MatchJSON(t, summary)

	testResult := ufm.GetTestResultsFromWorkflowData(outputData[1])
	require.Len(t, testResult, 1)

	require.Contains(t, "application/json; schema=local-unified-finding", outputData[2].GetContentType())
	localFindings, ok := outputData[2].GetPayload().([]byte)
	require.True(t, ok)
	snaps.MatchJSON(t, idRgxp.ReplaceAll(localFindings, nil))

	require.Contains(t, "application/json; schema=local-unified-summary", outputData[3].GetContentType())
	localSummary, ok := outputData[3].GetPayload().([]byte)
	require.True(t, ok)
	snaps.MatchJSON(t, localSummary)
}

func Test_RunSbomFlow_NoReachability_JSON(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ef := errors.NewErrorFactory(&nopLogger)
	mockIctx, mockTestClient, mockBsClient, orgID, sbomPath, sourceCodePath := setupTest(t, ctrl, true, false)
	ctx := t.Context()
	ctx = cmdctx.WithIctx(ctx, mockIctx)
	ctx = cmdctx.WithConfig(ctx, mockIctx.GetConfiguration())
	ctx = cmdctx.WithLogger(ctx, &nopLogger)
	ctx = cmdctx.WithErrorFactory(ctx, ef)
	ctx = cmdctx.WithProgressBar(ctx, &nopProgressBar)

	// This should now succeed with proper finding data
	legacyJSON, outputData, err := ostest.RunSbomFlow(ctx, mockTestClient, sbomPath, sourceCodePath, mockBsClient, orgID, nil, false)
	require.NoError(t, err)

	require.NotNil(t, legacyJSON)
	jsonBytes, err := json.Marshal(legacyJSON)
	require.NoError(t, err)
	snaps.MatchJSON(t, jsonBytes)

	require.NotNil(t, outputData)
	// Output data should contain standard summary and unified model test result
	require.Len(t, outputData, 2)

	require.Contains(t, "application/json; schema=test-summary", outputData[0].GetContentType())
	summary, ok := outputData[0].GetPayload().([]byte)
	require.True(t, ok)
	snaps.MatchJSON(t, summary)

	testResult := ufm.GetTestResultsFromWorkflowData(outputData[1])
	require.Len(t, testResult, 1)
}

func Test_RunSbomFlow_NoReachability_HumanReadable(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ef := errors.NewErrorFactory(&nopLogger)
	mockIctx, mockTestClient, mockBsClient, orgID, sbomPath, sourceCodePath := setupTest(t, ctrl, false, false)
	ctx := t.Context()
	ctx = cmdctx.WithIctx(ctx, mockIctx)
	ctx = cmdctx.WithConfig(ctx, mockIctx.GetConfiguration())
	ctx = cmdctx.WithLogger(ctx, &nopLogger)
	ctx = cmdctx.WithErrorFactory(ctx, ef)
	ctx = cmdctx.WithProgressBar(ctx, &nopProgressBar)

	// This should now succeed with proper finding data
	legacyJSON, outputData, err := ostest.RunSbomFlow(ctx, mockTestClient, sbomPath, sourceCodePath, mockBsClient, orgID, nil, false)
	require.NoError(t, err)

	require.Nil(t, legacyJSON)
	require.NotNil(t, outputData)
	// Output data should contain standard summary, unified model test result, local unified findings and local unified summary
	require.Len(t, outputData, 4)

	require.Contains(t, "application/json; schema=test-summary", outputData[0].GetContentType())
	summary, ok := outputData[0].GetPayload().([]byte)
	require.True(t, ok)
	snaps.MatchJSON(t, summary)

	testResult := ufm.GetTestResultsFromWorkflowData(outputData[1])
	require.Len(t, testResult, 1)

	require.Contains(t, "application/json; schema=local-unified-finding", outputData[2].GetContentType())
	localFindings, ok := outputData[2].GetPayload().([]byte)
	require.True(t, ok)
	snaps.MatchJSON(t, idRgxp.ReplaceAll(localFindings, nil))

	require.Contains(t, "application/json; schema=local-unified-summary", outputData[3].GetContentType())
	localSummary, ok := outputData[3].GetPayload().([]byte)
	require.True(t, ok)
	snaps.MatchJSON(t, localSummary)
}

//nolint:gocritic // Not important for tests.
func setupTest(
	t *testing.T,
	ctrl *gomock.Controller,
	jsonOutput bool,
	reachability bool,
) (workflow.InvocationContext, testapi.TestClient, bundlestore.Client, string, string, string) {
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

	act := testapi.FixAction{}
	act.FromUpgradePackageAdvice(testapi.UpgradePackageAdvice{
		Format:      testapi.UpgradePackageAdviceFormatUpgradePackageAdvice,
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
					// Attributes Inlined attributes included in the relationship, if it is expanded.
					//
					// Expansion is a Snyk variation on JSON API. See
					// https://snyk.roadie.so/docs/default/component/sweater-comb/standards/rest/#expansion
					Attributes *testapi.PolicyAttributes `json:"attributes,omitempty"`
					Id         uuid.UUID                 `json:"id"`
					Type       string                    `json:"type"`
				} `json:"data,omitempty"`
				Links testapi.IoSnykApiCommonRelatedLink `json:"links"`

				// Meta Free-form object that may contain non-standard information.
				Meta *testapi.IoSnykApiCommonMeta `json:"meta,omitempty"`
			} `json:"policy,omitempty"`
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
						Action:  &act,
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
	if reachability {
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
	} else {
		err = testSubject.FromSbomSubject(testapi.SbomSubject{
			Type:         testapi.SbomSubjectTypeSbom,
			SbomBundleId: "test-sbom-hash",
			Locator: testapi.LocalPathLocator{
				Paths: []string{
					sbomPath,
				},
				Type: testapi.LocalPath,
			},
		})
	}

	require.NoError(t, err)

	// Mock TestResult with comprehensive data
	mockTestResult := gafclientmocks.NewMockTestResult(ctrl)
	mockTestResult.EXPECT().GetExecutionState().Return(testapi.TestExecutionStatesFinished).AnyTimes()
	mockTestResult.EXPECT().Findings(gomock.Any()).Return([]testapi.FindingData{findingData}, true, nil).AnyTimes()
	mockTestResult.EXPECT().GetTestSubject().Return(&testSubject).AnyTimes()
	mockTestResult.EXPECT().GetEffectiveSummary().Return(summary).AnyTimes()
	mockTestResult.EXPECT().GetRawSummary().Return(summary).AnyTimes()

	passFail := testapi.Pass
	outcomeReason := testapi.TestOutcomeReasonOther
	// Mock calls for serialized test result
	mockTestResult.EXPECT().GetTestID().Return(&uuid.UUID{}).AnyTimes()
	mockTestResult.EXPECT().GetTestConfiguration().Return(&testapi.TestConfiguration{}).AnyTimes()
	mockTestResult.EXPECT().GetCreatedAt().Return(&time.Time{}).AnyTimes()
	mockTestResult.EXPECT().GetErrors().Return(&[]testapi.IoSnykApiCommonError{}).AnyTimes()
	mockTestResult.EXPECT().GetWarnings().Return(&[]testapi.IoSnykApiCommonError{}).AnyTimes()
	mockTestResult.EXPECT().GetPassFail().Return(&passFail).AnyTimes()
	mockTestResult.EXPECT().GetOutcomeReason().Return(&outcomeReason).AnyTimes()
	mockTestResult.EXPECT().SetMetadata(gomock.Any(), gomock.Any()).Return().AnyTimes()
	mockTestResult.EXPECT().GetMetadata().Return(make(map[string]interface{})).AnyTimes()
	mockTestResult.EXPECT().GetBreachedPolicies().Return(&testapi.PolicyRefSet{}).AnyTimes()

	var tsl testapi.TestSubjectLocator
	projectID := uuid.MustParse("5c520c95-a964-4de0-9284-02a16f9f88d5")
	err = tsl.FromProjectEntityLocator(testapi.ProjectEntityLocator{
		ProjectId: projectID,
		Type:      testapi.ProjectEntity,
	})
	require.NoError(t, err)
	mockTestResult.EXPECT().GetSubjectLocators().Return(util.Ptr([]testapi.TestSubjectLocator{tsl})).AnyTimes()

	// Mock TestHandle
	mockTestHandle := gafclientmocks.NewMockTestHandle(ctrl)
	mockTestHandle.EXPECT().Wait(gomock.Any()).Return(nil).Times(1)
	mockTestHandle.EXPECT().Result().Return(mockTestResult).Times(1)

	// Mock TestClient
	mockTestClient := gafclientmocks.NewMockTestClient(ctrl)
	mockTestClient.EXPECT().StartTest(gomock.Any(), gomock.Any()).Return(mockTestHandle, nil).Times(1)

	// Mock BundleStore Client
	mockBsClient := mocks.NewMockClient(ctrl)
	mockBsClient.EXPECT().UploadSBOM(gomock.Any(), sbomPath).Return("test-sbom-hash", nil).Times(1)
	if reachability {
		mockBsClient.EXPECT().UploadSourceCode(gomock.Any(), sourceCodePath).Return("test-source-hash", nil).Times(1)
	}

	// Mock Invocation Context
	mockConfig := configuration.New()
	mockConfig.Set(outputworkflow.OutputConfigKeyJSON, jsonOutput)
	mockConfig.Set(configuration.ORGANIZATION_SLUG, orgSlug)
	mockIctx := gafmocks.NewMockInvocationContext(ctrl)
	mockIctx.EXPECT().GetConfiguration().Return(mockConfig).AnyTimes()
	mockIctx.EXPECT().GetEnhancedLogger().Return(&nopLogger).AnyTimes()
	mockIctx.EXPECT().GetRuntimeInfo().Return(runtimeinfo.New()).AnyTimes()
	mockIctx.EXPECT().GetWorkflowIdentifier().Return(workflow.NewWorkflowIdentifier("test")).AnyTimes()

	return mockIctx, mockTestClient, mockBsClient, orgID, sbomPath, sourceCodePath
}
