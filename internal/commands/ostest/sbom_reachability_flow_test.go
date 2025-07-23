package ostest_test

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	gafmocks "github.com/snyk/go-application-framework/pkg/apiclients/mocks"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"

	"github.com/snyk/cli-extension-os-flows/internal/commands/ostest"
	"github.com/snyk/cli-extension-os-flows/internal/errors"
	"github.com/snyk/cli-extension-os-flows/internal/mocks"
)

//go:generate go run github.com/golang/mock/mockgen -package=mocks -destination=../../mocks/mock_bundlestore_client.go github.com/snyk/cli-extension-os-flows/internal/bundlestore Client

func Test_RunSbomReachabilityFlow_Success(t *testing.T) {
	logger := zerolog.Nop()
	ef := errors.NewErrorFactory(&logger)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	ctx := context.Background()
	sbomPath := "./testdata/bom.json"
	sourceCodePath := "./testdata/test_dir"
	orgID := "test-org-id"

	// Create realistic finding data
	findingID := uuid.New()
	cveID := "CVE-2024-12345"
	filePath := "package-lock.json"
	lineNum := 42

	// Create a mock Problem (CVE)
	var problem testapi.Problem
	err := problem.FromCveProblem(testapi.CveProblem{
		Id:     cveID,
		Source: testapi.Cve,
	})
	require.NoError(t, err)

	// Create a mock Location (SourceFile)
	var location testapi.FindingLocation
	err = location.FromSourceLocation(testapi.SourceLocation{
		FilePath: filePath,
		FromLine: lineNum,
		Type:     testapi.Source,
	})
	require.NoError(t, err)

	// Create mock FindingAttributes
	findingAttrs := testapi.FindingAttributes{
		CauseOfFailure: false,
		Description:    "Test vulnerability description",
		Evidence:       []testapi.Evidence{},
		FindingType:    testapi.FindingTypeSca,
		Key:            "TEST-FINDING-KEY",
		Locations:      []testapi.FindingLocation{location},
		Problems:       []testapi.Problem{problem},
		Rating:         testapi.Rating{Severity: testapi.SeverityHigh},
		Risk:           testapi.Risk{RiskScore: &testapi.RiskScore{Value: uint16(80)}},
		Title:          "Test High Severity Finding",
	}

	// Create mock FindingData
	findingDataType := testapi.Findings
	findingData := testapi.FindingData{
		Attributes: &findingAttrs,
		Id:         &findingID,
		Type:       &findingDataType,
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
	mockTestResult := gafmocks.NewMockTestResult(ctrl)
	mockTestResult.EXPECT().Findings(gomock.Any()).Return([]testapi.FindingData{findingData}, true, nil).Times(1)
	mockTestResult.EXPECT().GetTestSubject().Return(testSubject).AnyTimes()
	mockTestResult.EXPECT().GetEffectiveSummary().Return(summary).AnyTimes()
	mockTestResult.EXPECT().GetRawSummary().Return(summary).AnyTimes()

	// Mock TestHandle
	mockTestHandle := gafmocks.NewMockTestHandle(ctrl)
	mockTestHandle.EXPECT().Wait(gomock.Any()).Return(nil).Times(1)
	mockTestHandle.EXPECT().Result().Return(mockTestResult).Times(1)

	// Mock TestClient
	mockTestClient := gafmocks.NewMockTestClient(ctrl)
	mockTestClient.EXPECT().StartTest(gomock.Any(), gomock.Any()).Return(mockTestHandle, nil).Times(1)

	// Mock BundleStore Client
	mockBsClient := mocks.NewMockClient(ctrl)
	mockBsClient.EXPECT().UploadSBOM(ctx, sbomPath).Return("test-sbom-hash", nil).Times(1)
	mockBsClient.EXPECT().UploadSourceCode(ctx, sourceCodePath).Return("test-source-hash", nil).Times(1)

	// This should now succeed with proper finding data
	result, err := ostest.RunSbomReachabilityFlow(ctx, mockTestClient, ef, &logger, sbomPath, sourceCodePath, mockBsClient, orgID)

	require.NoError(t, err)
	require.NotNil(t, result)
	require.Len(t, result, 2) // Should return legacy data + summary data

	// Verify we got the expected workflow data types
	contentTypes := make([]string, len(result))
	for i, data := range result {
		contentTypes[i] = data.GetContentType()
	}

	require.Contains(t, contentTypes, "application/json")                      // legacy data
	require.Contains(t, contentTypes, "application/json; schema=test-summary") // summary data
}
