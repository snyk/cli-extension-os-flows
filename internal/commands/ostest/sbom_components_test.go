package ostest_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
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
	"github.com/snyk/cli-extension-os-flows/internal/common"
	"github.com/snyk/cli-extension-os-flows/internal/deeproxy"
	"github.com/snyk/cli-extension-os-flows/internal/errors"
	"github.com/snyk/cli-extension-os-flows/internal/outputworkflow"
	"github.com/snyk/cli-extension-os-flows/internal/presenters"
	"github.com/snyk/cli-extension-os-flows/internal/util"
	"github.com/snyk/cli-extension-os-flows/internal/util/testfactories"
)

const multiComponentSbomPath = "./testdata/bom.json"

func componentFinding(t *testing.T, title, componentKey string) testapi.FindingData {
	t.Helper()

	var problem testapi.Problem
	ecosystem := testapi.SnykvulndbPackageEcosystem{}
	require.NoError(t, ecosystem.FromSnykvulndbBuildPackageEcosystem(testapi.SnykvulndbBuildPackageEcosystem{
		Language:       "js",
		PackageManager: "npm",
		Type:           testapi.Build,
	}))
	require.NoError(t, problem.FromSnykVulnProblem(testapi.SnykVulnProblem{
		Id:             "snyk-vuln-" + title,
		PackageName:    "foo",
		PackageVersion: "0.0.0",
		Ecosystem:      ecosystem,
	}))

	findingID := uuid.New()
	findingType := testapi.Findings
	return testapi.FindingData{
		Id:   &findingID,
		Type: &findingType,
		Attributes: &testapi.FindingAttributes{
			ComponentKey: util.Ptr(componentKey),
			Description:  "description of " + title,
			Evidence:     []testapi.Evidence{testfactories.NewShimDependencyPathEvidence(t, "root@1.0.0", "foo@0.0.0")},
			FindingType:  testapi.FindingTypeSca,
			Key:          "KEY-" + title,
			Locations:    []testapi.FindingLocation{testfactories.NewShimPackageLocation(t, "foo@0.0.0")},
			Problems:     []testapi.Problem{problem},
			Rating:       testapi.Rating{Severity: testapi.SeverityHigh},
			Title:        title,
		},
	}
}

func setupMultiComponentSbomTest(
	t *testing.T,
	ctrl *gomock.Controller,
	jsonOutput bool,
	components []testapi.TestComponent,
	findings []testapi.FindingData,
	metadata map[string]interface{},
) (*gafmocks.MockInvocationContext, testapi.TestClient, *fileupload.FakeClient, deeproxy.Client, uuid.UUID) {
	t.Helper()

	summary := &testapi.FindingSummary{Count: uint32(len(findings))} //nolint:gosec // Small, test-controlled value.

	result := gafclientmocks.NewMockTestResult(ctrl)
	result.EXPECT().GetExecutionState().Return(testapi.TestExecutionStatesFinished).AnyTimes()
	result.EXPECT().Findings(gomock.Any()).Return(findings, true, nil).AnyTimes()
	result.EXPECT().GetTestID().Return(&uuid.UUID{}).AnyTimes()
	result.EXPECT().GetTestConfiguration().Return(&testapi.TestConfiguration{}).AnyTimes()
	result.EXPECT().GetCreatedAt().Return(&time.Time{}).AnyTimes()
	result.EXPECT().GetErrors().Return(&[]testapi.IoSnykApiCommonError{}).AnyTimes()
	result.EXPECT().GetWarnings().Return(&[]testapi.IoSnykApiCommonError{}).AnyTimes()
	result.EXPECT().GetPassFail().Return(util.Ptr(testapi.Pass)).AnyTimes()
	result.EXPECT().GetOutcomeReason().Return(util.Ptr(testapi.TestOutcomeReasonOther)).AnyTimes()
	result.EXPECT().GetEffectiveSummary().Return(summary).AnyTimes()
	result.EXPECT().GetRawSummary().Return(summary).AnyTimes()
	if metadata == nil {
		metadata = map[string]interface{}{}
	}
	result.EXPECT().SetMetadata(gomock.Any(), gomock.Any()).DoAndReturn(func(key string, value interface{}) {
		metadata[key] = value
	}).AnyTimes()
	result.EXPECT().GetMetadata().Return(metadata).AnyTimes()
	result.EXPECT().GetMetadataValue(gomock.Any()).DoAndReturn(func(key string) interface{} {
		return metadata[key]
	}).AnyTimes()
	result.EXPECT().Get(testapi.TestResultTestSubject).Return(nil).AnyTimes()
	result.EXPECT().Get(testapi.TestResultSubjectLocators).Return(nil).AnyTimes()
	result.EXPECT().Get(testapi.TestResultBreachedPolicies).Return(&testapi.PolicyRefSet{}).AnyTimes()
	result.EXPECT().Get(testapi.TestResultRawSummary).Return(summary).AnyTimes()
	result.EXPECT().Get(testapi.TestResultTestFacts).Return(nil).AnyTimes()
	result.EXPECT().Get(testapi.TestResultMetadata).DoAndReturn(func(testapi.TestResultKeys) interface{} {
		return metadata
	}).AnyTimes()
	result.EXPECT().Get(testapi.TestResultComponents).Return(&components).AnyTimes()

	handle := gafclientmocks.NewMockTestHandle(ctrl)
	handle.EXPECT().Wait(gomock.Any()).Return(nil).Times(1)
	handle.EXPECT().Result().Return(result).Times(1)

	client := gafclientmocks.NewMockTestClient(ctrl)
	client.EXPECT().StartTest(gomock.Any(), gomock.Any()).Return(handle, nil).Times(1)

	cfg := configuration.New()
	cfg.Set(outputworkflow.OutputConfigKeyJSON, jsonOutput)
	cfg.Set(configuration.ORGANIZATION_SLUG, "test-org-slug")

	ui := gafmocks.NewMockUserInterface(ctrl)
	ui.EXPECT().Output(gomock.Any()).Return(nil).AnyTimes()
	ui.EXPECT().OutputError(gomock.Any()).Return(nil).AnyTimes()

	ictx := gafmocks.NewMockInvocationContext(ctrl)
	ictx.EXPECT().GetConfiguration().Return(cfg).AnyTimes()
	ictx.EXPECT().GetEnhancedLogger().Return(&nopLogger).AnyTimes()
	ictx.EXPECT().GetRuntimeInfo().Return(runtimeinfo.New()).AnyTimes()
	ictx.EXPECT().GetWorkflowIdentifier().Return(workflow.NewWorkflowIdentifier("test")).AnyTimes()
	ictx.EXPECT().GetUserInterface().Return(ui).AnyTimes()

	return ictx, client, fileupload.NewFakeClient(), deeproxy.NewFakeClient(deeproxy.AllowList{}, nil), uuid.New()
}

func sbomTestContext(t *testing.T, ictx *gafmocks.MockInvocationContext) context.Context {
	t.Helper()

	c := cmdctx.WithIctx(t.Context(), ictx)
	c = cmdctx.WithConfig(c, ictx.GetConfiguration())
	c = cmdctx.WithLogger(c, &nopLogger)
	c = cmdctx.WithErrorFactory(c, errors.NewErrorFactory(&nopLogger))
	c = cmdctx.WithProgressBar(c, &nopProgressBar)
	return c
}

func Test_RunSbomFlow_SplitsHumanReadableResultsByComponent(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	appA := "pkg:npm/app-a@1.0.0"
	appB := "pkg:npm/app-b@2.0.0"
	clean := "pkg:npm/clean@3.0.0"

	ictx, testClient, ffc, fdc, orgID := setupMultiComponentSbomTest(t, ctrl, false,
		[]testapi.TestComponent{
			{Key: appA, ScanType: testapi.FindingTypeSca},
			{Key: appB, ScanType: testapi.FindingTypeSca},
			{Key: clean, ScanType: testapi.FindingTypeSca},
		},
		[]testapi.FindingData{
			componentFinding(t, "a1", appA),
			componentFinding(t, "b1", appB),
			componentFinding(t, "a2", appA),
		},
		nil,
	)

	_, outputData, err := common.RunSbomFlow(
		sbomTestContext(t, ictx),
		multiComponentSbomPath,
		common.FlowClients{TestClient: testClient, FileUploadClient: ffc, DeeproxyClient: fdc},
		orgID,
		nil,
		nil,
		ostest.RunTestWithResourcesByComponent,
	)
	require.NoError(t, err)

	require.Len(t, outputData, 10)

	summaries := unifiedSummariesFrom(t, outputData)
	require.Len(t, summaries, 3)

	assert.Equal(t, []string{appA, appB, clean}, []string{
		summaries[0].DisplayTargetFile, summaries[1].DisplayTargetFile, summaries[2].DisplayTargetFile,
	})
	assert.Equal(t, []string{appA, appB, clean}, []string{
		summaries[0].ProjectName, summaries[1].ProjectName, summaries[2].ProjectName,
	})

	for _, summary := range summaries {
		assert.Zero(t, summary.DependencyCount)
	}

	findingsByComponent := unifiedFindingsFrom(t, outputData)
	require.Len(t, findingsByComponent, 3)
	assert.Equal(t, []string{"a1", "a2"}, titlesOf(findingsByComponent[0]))
	assert.Equal(t, []string{"b1"}, titlesOf(findingsByComponent[1]))
	assert.Empty(t, findingsByComponent[2], "a component without findings still gets its own result")

	testResults := ufm.GetTestResultsFromWorkflowData(outputData[len(outputData)-1])
	require.Len(t, testResults, 3)

	for i, key := range []string{appA, appB, clean} {
		metadata, ok := testResults[i].Get(testapi.TestResultMetadata).(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, key, metadata["display-target-file"])
		assert.Equal(t, "testdata", metadata["target-directory"], "the SBOM's directory is shared by every component")
		assert.EqualValues(t, 0, metadata["dependency-count"])
	}

	perComponentFindings := make([][]testapi.FindingData, 0, len(testResults))
	for _, result := range testResults {
		f, _, findingsErr := result.Findings(t.Context())
		require.NoError(t, findingsErr)
		perComponentFindings = append(perComponentFindings, f)
	}
	assert.Equal(t, []string{"a1", "a2"}, titlesOf(perComponentFindings[0]))
	assert.Equal(t, []string{"b1"}, titlesOf(perComponentFindings[1]))
	assert.Empty(t, perComponentFindings[2])
}

func Test_RunSbomFlow_SplitsLegacyJSONByComponent(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	appA := "pkg:npm/app-a@1.0.0"
	appB := "pkg:npm/app-b@2.0.0"
	projectA := uuid.New()

	ictx, testClient, ffc, fdc, orgID := setupMultiComponentSbomTest(t, ctrl, true,
		[]testapi.TestComponent{
			{Key: appA, ProjectId: &projectA, ScanType: testapi.FindingTypeSca},
			{Key: appB, ScanType: testapi.FindingTypeSca},
		},
		[]testapi.FindingData{
			componentFinding(t, "a1", appA),
			componentFinding(t, "b1", appB),
		},
		nil,
	)

	legacyJSON, _, err := common.RunSbomFlow(
		sbomTestContext(t, ictx),
		multiComponentSbomPath,
		common.FlowClients{TestClient: testClient, FileUploadClient: ffc, DeeproxyClient: fdc},
		orgID,
		nil,
		nil,
		ostest.RunTestWithResourcesByComponent,
	)
	require.NoError(t, err)

	require.Len(t, legacyJSON, 2)

	require.NotNil(t, legacyJSON[0].ProjectName)
	assert.Equal(t, appA, *legacyJSON[0].ProjectName)
	assert.Equal(t, appA, legacyJSON[0].DisplayTargetFile)
	require.NotNil(t, legacyJSON[0].TargetFile)
	assert.Equal(t, multiComponentSbomPath, *legacyJSON[0].TargetFile)
	require.NotNil(t, legacyJSON[0].ProjectId)
	assert.Equal(t, projectA.String(), *legacyJSON[0].ProjectId)
	assert.Len(t, legacyJSON[0].Vulnerabilities, 1)

	require.NotNil(t, legacyJSON[1].ProjectName)
	assert.Equal(t, appB, *legacyJSON[1].ProjectName)
	assert.Nil(t, legacyJSON[1].ProjectId)
	assert.Len(t, legacyJSON[1].Vulnerabilities, 1)
}

func Test_RunSbomFlow_SingleResultWhenNoComponentsReported(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	finding := componentFinding(t, "a1", "")
	finding.Attributes.ComponentKey = nil

	ictx, testClient, ffc, fdc, orgID := setupMultiComponentSbomTest(t, ctrl, true,
		[]testapi.TestComponent{},
		[]testapi.FindingData{finding},
		nil,
	)

	legacyJSON, outputData, err := common.RunSbomFlow(
		sbomTestContext(t, ictx),
		multiComponentSbomPath,
		common.FlowClients{TestClient: testClient, FileUploadClient: ffc, DeeproxyClient: fdc},
		orgID,
		nil,
		nil,
		ostest.RunTestWithResourcesByComponent,
	)
	require.NoError(t, err)

	require.Len(t, legacyJSON, 1)
	assert.Equal(t, multiComponentSbomPath, legacyJSON[0].DisplayTargetFile)
	assert.Nil(t, legacyJSON[0].ProjectName)

	testResults := ufm.GetTestResultsFromWorkflowData(outputData[len(outputData)-1])
	require.Len(t, testResults, 1)
	metadata, ok := testResults[0].Get(testapi.TestResultMetadata).(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, multiComponentSbomPath, metadata["display-target-file"])
}

func Test_RunSbomFlow_ReportsTheAssetOnEveryComponent(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	appA := "pkg:npm/app-a@1.0.0"
	appB := "pkg:npm/app-b@2.0.0"
	assetLink := "https://app.snyk.io/asset/1234"
	reportURL := "https://app.snyk.io/report/5678"

	ictx, testClient, ffc, fdc, orgID := setupMultiComponentSbomTest(t, ctrl, false,
		[]testapi.TestComponent{
			{Key: appA, ScanType: testapi.FindingTypeSca},
			{Key: appB, ScanType: testapi.FindingTypeSca},
		},
		[]testapi.FindingData{
			componentFinding(t, "a1", appA),
			componentFinding(t, "b1", appB),
		},
		map[string]interface{}{"asset": assetLink, "report-url": reportURL},
	)

	_, outputData, err := common.RunSbomFlow(
		sbomTestContext(t, ictx),
		multiComponentSbomPath,
		common.FlowClients{TestClient: testClient, FileUploadClient: ffc, DeeproxyClient: fdc},
		orgID,
		nil,
		nil,
		ostest.RunTestWithResourcesByComponent,
	)
	require.NoError(t, err)

	testResults := ufm.GetTestResultsFromWorkflowData(outputData[len(outputData)-1])
	require.Len(t, testResults, 2)

	for i := range testResults {
		metadata, ok := testResults[i].Get(testapi.TestResultMetadata).(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, assetLink, metadata["asset"], "component %d", i)
		assert.Equal(t, reportURL, metadata["report-url"], "component %d", i)
	}

	summaries := unifiedSummariesFrom(t, outputData)
	require.Len(t, summaries, 2)
	assert.Equal(t, assetLink, summaries[0].AssetLink)
	assert.Equal(t, assetLink, summaries[1].AssetLink)
}

func unifiedSummariesFrom(t *testing.T, data []workflow.Data) []presenters.SummaryPayload {
	t.Helper()

	var summaries []presenters.SummaryPayload
	for _, d := range data {
		if d.GetContentType() != "application/json; schema=local-unified-summary" {
			continue
		}
		payload, ok := d.GetPayload().([]byte)
		require.True(t, ok)

		var summary presenters.SummaryPayload
		require.NoError(t, json.Unmarshal(payload, &summary))
		summaries = append(summaries, summary)
	}
	return summaries
}

func unifiedFindingsFrom(t *testing.T, data []workflow.Data) [][]testapi.FindingData {
	t.Helper()

	var all [][]testapi.FindingData
	for _, d := range data {
		if d.GetContentType() != "application/json; schema=local-unified-finding" {
			continue
		}
		payload, ok := d.GetPayload().([]byte)
		require.True(t, ok)

		var findings []testapi.FindingData
		require.NoError(t, json.Unmarshal(payload, &findings))
		all = append(all, findings)
	}
	return all
}
