//nolint:revive // Interferes with inline types from testapi.
package ostest_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/snyk/dep-graph/go/pkg/depgraph"
	"github.com/snyk/go-application-framework/pkg/apiclients/fileupload"
	gafclientmocks "github.com/snyk/go-application-framework/pkg/apiclients/mocks"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	gafmocks "github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/snyk/go-application-framework/pkg/utils/ufm"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	"github.com/snyk/cli-extension-os-flows/internal/commands/ostest"
	service "github.com/snyk/cli-extension-os-flows/internal/common"
	"github.com/snyk/cli-extension-os-flows/internal/outputworkflow"
	"github.com/snyk/cli-extension-os-flows/internal/util"
)

func Test_RunDflyDepgraphFlow_JSON(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	orgID := uuid.New()
	mockIctx := setupInvocationContext(t, ctrl, true)
	mockTestClient := setupTestClient(t, ctrl)
	ffc := fileupload.NewFakeClient()
	fdr := service.NewFakeDepgraphResolver([]service.DepgraphWithIdentity{
		{
			Identity: service.Identity{
				TargetFile: "proj/package.json",
			},
			DepGraph: &depgraph.DepGraph{
				SchemaVersion: "1.2.0",
				PkgManager:    depgraph.PkgManager{Name: "npm"},
				Pkgs: []depgraph.Pkg{
					{ID: "proj@1.0.0", Info: depgraph.PkgInfo{Name: "proj", Version: "1.0.0"}},
				},
				Graph: depgraph.Graph{
					RootNodeID: "root",
				},
			},
		},
	}, nil)

	ctx := t.Context()
	ctx = cmdctx.WithIctx(ctx, mockIctx)
	ctx = cmdctx.WithLogger(ctx, &nopLogger)
	ctx = cmdctx.WithProgressBar(ctx, &nopProgressBar)
	ctx = cmdctx.WithConfig(ctx, mockIctx.GetConfiguration())

	legacyJSON, outputData, err := ostest.RunDflyDepgraphFlow(
		ctx,
		".",
		fdr,
		ostest.FlowClients{FileUploadClient: ffc, TestClient: mockTestClient},
		orgID,
		nil,
		nil,
	)
	require.NoError(t, err)

	// We expect one upload, containing a depgraph file
	assert.Equal(t, 1, ffc.GetUploadCount())
	paths := ffc.GetRevisionPaths(ffc.GetLastRevisionID())
	require.Len(t, paths, 1)
	assert.Contains(t, paths[0], "depgraph-")

	assert.Len(t, legacyJSON, 1)
	jsonBts, err := json.Marshal(legacyJSON[0])
	require.NoError(t, err)
	snaps.MatchJSON(t, jsonBts)

	// Output data should contain standard summary and unified model test result
	require.Len(t, outputData, 2)
	require.Contains(t, "application/json; schema=test-summary", outputData[0].GetContentType())
	summary, ok := outputData[0].GetPayload().([]byte)
	require.True(t, ok)
	snaps.MatchJSON(t, summary)

	testResult := ufm.GetTestResultsFromWorkflowData(outputData[1])
	require.Len(t, testResult, 1)
}

func Test_RunDflyDepgraphFlow_HumanReadable(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	orgID := uuid.New()
	mockIctx := setupInvocationContext(t, ctrl, false)
	mockTestClient := setupTestClient(t, ctrl)
	ffc := fileupload.NewFakeClient()
	fdr := service.NewFakeDepgraphResolver([]service.DepgraphWithIdentity{
		{
			Identity: service.Identity{
				TargetFile: "proj/package.json",
			},
			DepGraph: &depgraph.DepGraph{
				SchemaVersion: "1.2.0",
				PkgManager:    depgraph.PkgManager{Name: "npm"},
				Pkgs: []depgraph.Pkg{
					{ID: "proj@1.0.0", Info: depgraph.PkgInfo{Name: "proj", Version: "1.0.0"}},
				},
				Graph: depgraph.Graph{
					RootNodeID: "root",
				},
			},
		},
	}, nil)

	ctx := t.Context()
	ctx = cmdctx.WithIctx(ctx, mockIctx)
	ctx = cmdctx.WithLogger(ctx, &nopLogger)
	ctx = cmdctx.WithProgressBar(ctx, &nopProgressBar)
	ctx = cmdctx.WithConfig(ctx, mockIctx.GetConfiguration())

	legacyJSON, outputData, err := ostest.RunDflyDepgraphFlow(
		ctx,
		".",
		fdr,
		ostest.FlowClients{FileUploadClient: ffc, TestClient: mockTestClient},
		orgID,
		nil,
		nil,
	)
	require.NoError(t, err)

	// We expect one upload, containing a depgraph file
	assert.Equal(t, 1, ffc.GetUploadCount())
	paths := ffc.GetRevisionPaths(ffc.GetLastRevisionID())
	require.Len(t, paths, 1)
	assert.Contains(t, paths[0], "depgraph-")

	assert.Len(t, legacyJSON, 0)

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

func Test_RunDflyDepgraphFlow_UploadingDepgraphsFail(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	orgID := uuid.New()
	mockIctx := setupInvocationContext(t, ctrl, true)
	mockTestClient := gafclientmocks.NewMockTestClient(ctrl)
	ffc := fileupload.NewFakeClient()
	ffc.WithError(assert.AnError)
	fdr := service.NewFakeDepgraphResolver([]service.DepgraphWithIdentity{
		{
			Identity: service.Identity{
				TargetFile: "proj/package.json",
			},
			DepGraph: &depgraph.DepGraph{
				SchemaVersion: "1.2.0",
				PkgManager:    depgraph.PkgManager{Name: "npm"},
				Pkgs: []depgraph.Pkg{
					{ID: "proj@1.0.0", Info: depgraph.PkgInfo{Name: "proj", Version: "1.0.0"}},
				},
				Graph: depgraph.Graph{
					RootNodeID: "root",
				},
			},
		},
	}, nil)

	ctx := t.Context()
	ctx = cmdctx.WithIctx(ctx, mockIctx)
	ctx = cmdctx.WithLogger(ctx, &nopLogger)
	ctx = cmdctx.WithProgressBar(ctx, &nopProgressBar)
	ctx = cmdctx.WithConfig(ctx, mockIctx.GetConfiguration())

	_, _, err := ostest.RunDflyDepgraphFlow(ctx, ".", fdr, ostest.FlowClients{FileUploadClient: ffc, TestClient: mockTestClient}, orgID, nil, nil)
	assert.ErrorContains(t, err, "failed to upload dependency graphs")
}

func Test_RunDflyDepgraphFlow_DepgraphResolverFails(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	orgID := uuid.New()
	mockIctx := setupInvocationContext(t, ctrl, true)
	mockTestClient := gafclientmocks.NewMockTestClient(ctrl)
	ffc := fileupload.NewFakeClient()
	fdr := service.NewFakeDepgraphResolver(nil, assert.AnError)

	ctx := t.Context()
	ctx = cmdctx.WithIctx(ctx, mockIctx)
	ctx = cmdctx.WithLogger(ctx, &nopLogger)
	ctx = cmdctx.WithProgressBar(ctx, &nopProgressBar)
	ctx = cmdctx.WithConfig(ctx, mockIctx.GetConfiguration())

	_, _, err := ostest.RunDflyDepgraphFlow(ctx, ".", fdr, ostest.FlowClients{FileUploadClient: ffc, TestClient: mockTestClient}, orgID, nil, nil)
	assert.ErrorContains(t, err, "failed to extract dependency graphs")
}

func setupInvocationContext(t *testing.T, ctrl *gomock.Controller, jsonOutput bool) *gafmocks.MockInvocationContext {
	t.Helper()
	orgSlug := "test-org-slug"
	fakeConfig := configuration.New()
	fakeConfig.Set(outputworkflow.OutputConfigKeyJSON, jsonOutput)
	fakeConfig.Set(configuration.ORGANIZATION_SLUG, orgSlug)

	mockUI := gafmocks.NewMockUserInterface(ctrl)
	mockUI.EXPECT().Output(gomock.Any()).Return(nil).Times(0)

	mockIctx := gafmocks.NewMockInvocationContext(ctrl)
	mockIctx.EXPECT().GetConfiguration().Return(fakeConfig).AnyTimes()
	mockIctx.EXPECT().GetEnhancedLogger().Return(&nopLogger).AnyTimes()
	mockIctx.EXPECT().GetRuntimeInfo().Return(runtimeinfo.New()).AnyTimes()
	mockIctx.EXPECT().GetWorkflowIdentifier().Return(workflow.NewWorkflowIdentifier("test")).AnyTimes()
	mockIctx.EXPECT().GetUserInterface().Return(mockUI).AnyTimes()

	return mockIctx
}

func setupTestClient(t *testing.T, ctrl *gomock.Controller) *gafclientmocks.MockTestClient {
	t.Helper()
	summary := &testapi.FindingSummary{
		Count: 1,
		CountBy: &map[string]map[string]uint32{
			"severity": {
				"high": 1,
			},
		},
	}

	mockTestResult := gafclientmocks.NewMockTestResult(ctrl)
	mockTestResult.EXPECT().GetExecutionState().Return(testapi.TestExecutionStatesFinished).AnyTimes()
	mockTestResult.EXPECT().Findings(gomock.Any()).Return([]testapi.FindingData{aFinding(t)}, true, nil).AnyTimes()
	mockTestResult.EXPECT().GetTestSubject().Return(nil).AnyTimes()
	mockTestResult.EXPECT().GetEffectiveSummary().Return(summary).AnyTimes()
	mockTestResult.EXPECT().GetRawSummary().Return(summary).AnyTimes()

	var tsl testapi.TestSubjectLocator
	projectID := uuid.MustParse("5c520c95-a964-4de0-9284-02a16f9f88d5")
	err := tsl.FromProjectEntityLocator(testapi.ProjectEntityLocator{
		ProjectId: projectID,
		Type:      testapi.ProjectEntity,
	})
	require.NoError(t, err)

	passFail := testapi.Pass
	outcomeReason := testapi.TestOutcomeReasonOther
	mockTestResult.EXPECT().GetSubjectLocators().Return(util.Ptr([]testapi.TestSubjectLocator{tsl})).AnyTimes()
	mockTestResult.EXPECT().GetTestID().Return(&uuid.UUID{}).AnyTimes()
	mockTestResult.EXPECT().GetTestConfiguration().Return(&testapi.TestConfiguration{}).AnyTimes()
	mockTestResult.EXPECT().GetCreatedAt().Return(&time.Time{}).AnyTimes()
	mockTestResult.EXPECT().GetErrors().Return(&[]testapi.IoSnykApiCommonError{}).AnyTimes()
	mockTestResult.EXPECT().GetWarnings().Return(&[]testapi.IoSnykApiCommonError{}).AnyTimes()
	mockTestResult.EXPECT().GetPassFail().Return(&passFail).AnyTimes()
	mockTestResult.EXPECT().GetOutcomeReason().Return(&outcomeReason).AnyTimes()
	mockTestResult.EXPECT().SetMetadata(gomock.Any(), gomock.Any()).Return().AnyTimes()
	mockTestResult.EXPECT().GetMetadata().Return(make(map[string]interface{})).AnyTimes()
	mockTestResult.EXPECT().GetTestFacts().Return(nil).AnyTimes()
	mockTestResult.EXPECT().GetBreachedPolicies().Return(&testapi.PolicyRefSet{}).AnyTimes()

	mockTestHandle := gafclientmocks.NewMockTestHandle(ctrl)
	mockTestHandle.EXPECT().Wait(gomock.Any()).Return(nil).Times(1)
	mockTestHandle.EXPECT().Result().Return(mockTestResult).Times(1)

	mockTestClient := gafclientmocks.NewMockTestClient(ctrl)
	mockTestClient.EXPECT().StartTest(gomock.Any(), gomock.Any()).Return(mockTestHandle, nil).Times(1)

	return mockTestClient
}

func aFinding(t *testing.T) testapi.FindingData {
	t.Helper()

	vulnID := "snyk-vuln-123"
	ecosystem := testapi.SnykvulndbPackageEcosystem{}
	err := ecosystem.FromSnykvulndbBuildPackageEcosystem(testapi.SnykvulndbBuildPackageEcosystem{
		Language:       "js",
		PackageManager: "npm",
		Type:           testapi.Build,
	})
	require.NoError(t, err)
	vulnTime, err := time.Parse(time.RFC3339, "2025-07-28T17:11:43+03:00")
	require.NoError(t, err)
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

	var location testapi.FindingLocation
	err = location.FromPackageLocation(testapi.PackageLocation{
		Package: testapi.Package{
			Name:    "foo",
			Version: "0.0.0",
		},
		Type: testapi.PackageLocationTypePackage,
	})
	require.NoError(t, err)

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

	findingID := uuid.New()
	findingDataType := testapi.Findings
	return testapi.FindingData{
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
}
