//nolint:revive // Interferes with inline types from testapi.
package transform_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/apiclients/mocks"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/legacy/definitions"
	"github.com/snyk/cli-extension-os-flows/internal/legacy/transform"
	"github.com/snyk/cli-extension-os-flows/internal/util"
)

func TestProcessProblemForVuln_Identifiers(t *testing.T) {
	// Setup valid problems
	cveProblem := &testapi.Problem{}
	err := cveProblem.FromCveProblem(testapi.CveProblem{Id: "cve-problem-id", Source: testapi.Cve})
	require.NoError(t, err)

	cweProblem := &testapi.Problem{}
	err = cweProblem.FromCweProblem(testapi.CweProblem{Id: "cwe-problem-id", Source: testapi.Cwe})
	require.NoError(t, err)

	ghsaProblem := &testapi.Problem{}
	err = ghsaProblem.FromGithubSecurityAdvisoryProblem(testapi.GithubSecurityAdvisoryProblem{Id: "ghsa-problem-id", Source: testapi.Ghsa})
	require.NoError(t, err)

	// Setup invalid problem
	malformedProblem := &testapi.Problem{} // empty union

	tests := []struct {
		name        string
		vuln        *definitions.Vulnerability
		problem     *testapi.Problem
		shouldError bool
		assertFunc  func(t *testing.T, v *definitions.Vulnerability)
	}{
		{
			name:    "should add CVE identifier to empty vulnerability",
			vuln:    &definitions.Vulnerability{},
			problem: cveProblem,
			assertFunc: func(t *testing.T, v *definitions.Vulnerability) {
				t.Helper()
				require.NotNil(t, v.Identifiers)
				require.Len(t, v.Identifiers.CVE, 1)
				assert.Equal(t, "cve-problem-id", v.Identifiers.CVE[0])
				require.Len(t, v.Identifiers.CWE, 0)
			},
		},
		{
			name:    "should add CWE identifier to empty vulnerability",
			vuln:    &definitions.Vulnerability{},
			problem: cweProblem,
			assertFunc: func(t *testing.T, v *definitions.Vulnerability) {
				t.Helper()
				require.NotNil(t, v.Identifiers)
				require.Len(t, v.Identifiers.CWE, 1)
				assert.Equal(t, "cwe-problem-id", v.Identifiers.CWE[0])
				require.Len(t, v.Identifiers.CVE, 0)
			},
		},
		{
			name:    "should add GHSA identifier to empty vulnerability",
			vuln:    &definitions.Vulnerability{},
			problem: ghsaProblem,
			assertFunc: func(t *testing.T, v *definitions.Vulnerability) {
				t.Helper()
				require.NotNil(t, v.Identifiers)
				require.Len(t, *v.Identifiers.GHSA, 1)
				assert.Equal(t, "ghsa-problem-id", (*v.Identifiers.GHSA)[0])
				require.Len(t, v.Identifiers.CVE, 0)
			},
		},
		{
			name: "should append CWE identifier to existing CVE",
			vuln: &definitions.Vulnerability{
				Identifiers: &definitions.Identifiers{
					CVE: []string{"existing-cve"},
					CWE: []string{},
				},
			},
			problem: cweProblem,
			assertFunc: func(t *testing.T, v *definitions.Vulnerability) {
				t.Helper()
				require.NotNil(t, v.Identifiers)
				require.Len(t, v.Identifiers.CWE, 1)
				assert.Equal(t, "cwe-problem-id", v.Identifiers.CWE[0])
				require.Len(t, v.Identifiers.CVE, 1)
				assert.Equal(t, "existing-cve", v.Identifiers.CVE[0])
			},
		},
		{
			name:        "should error on malformed problem",
			vuln:        &definitions.Vulnerability{},
			problem:     malformedProblem,
			shouldError: true,
			assertFunc: func(t *testing.T, v *definitions.Vulnerability) {
				t.Helper()
				assert.Nil(t, v.Identifiers)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := zerolog.Nop()
			err := transform.ProcessProblemForVuln(tt.vuln, tt.problem, &logger)

			if tt.shouldError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			if tt.assertFunc != nil {
				tt.assertFunc(t, tt.vuln)
			}
		})
	}
}

func TestProcessingEvidenceForFinding(t *testing.T) {
	// Set up a dependency list for evidence.
	testDepList := []string{
		"thing@2.0.1",
		"bob@4.2.0",
		"snackdog@1.2.3",
	}
	// Create a package list based on the testDepList.
	packageList := []testapi.Package{}
	for _, dep := range testDepList {
		parts := strings.Split(dep, "@")
		packageList = append(packageList, testapi.Package{
			Name:    parts[0],
			Version: parts[1],
		})
	}

	// Test a dep path evidence with deps.
	depPathEv := &testapi.Evidence{}
	err := depPathEv.FromDependencyPathEvidence(testapi.DependencyPathEvidence{
		Path:   packageList,
		Source: testapi.DependencyPath,
	})
	require.NoError(t, err)

	// Test an empty dep path evidence.
	emptyDepPathEv := &testapi.Evidence{}
	err = emptyDepPathEv.FromDependencyPathEvidence(testapi.DependencyPathEvidence{
		Path:   []testapi.Package{},
		Source: testapi.DependencyPath,
	})
	require.NoError(t, err)

	// Test an exec flow evidence.
	execFlowEv := &testapi.Evidence{}
	err = execFlowEv.FromExecutionFlowEvidence(testapi.ExecutionFlowEvidence{
		Flow:   []testapi.FileRegion{},
		Source: testapi.ExecutionFlow,
	})
	require.NoError(t, err)

	// Test other flow evidence.
	otherFlowEv := &testapi.Evidence{}
	err = otherFlowEv.FromOtherEvidence(testapi.OtherEvidence{
		Source: testapi.OtherEvidenceSourceOther,
	})
	require.NoError(t, err)

	// Test reachability evidence for REACHABLE.
	reachableEv := &testapi.Evidence{}
	err = reachableEv.FromReachabilityEvidence(testapi.ReachabilityEvidence{
		Reachability: testapi.ReachabilityTypeFunction,
		Source:       testapi.Reachability,
	})
	require.NoError(t, err)

	// Test reachability evidence for NOT_REACHABLE.
	notReachableEv := &testapi.Evidence{}
	err = notReachableEv.FromReachabilityEvidence(testapi.ReachabilityEvidence{
		Reachability: testapi.ReachabilityTypeNoInfo,
		Source:       testapi.Reachability,
	})
	require.NoError(t, err)

	tests := []struct {
		ev            *testapi.Evidence
		expectedFrom  []string
		expectedReach *definitions.Reachability
		shouldErr     bool
	}{
		{&testapi.Evidence{}, nil, nil, true},
		{emptyDepPathEv, []string{}, nil, false},
		{depPathEv, testDepList, nil, false},
		{execFlowEv, nil, nil, false},  // Exec flow not yet supported.
		{otherFlowEv, nil, nil, false}, // Other flow not yet supported.
		{reachableEv, nil, util.Ptr(definitions.REACHABLE), false},
		{notReachableEv, nil, util.Ptr(definitions.NOTREACHABLE), false},
	}

	for _, tt := range tests {
		vuln := &definitions.Vulnerability{From: []string{}}
		err := transform.ProcessEvidenceForFinding(vuln, tt.ev)
		if tt.shouldErr {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
		}
		if tt.expectedFrom != nil {
			require.EqualValues(t, vuln.From, tt.expectedFrom)
		} else {
			require.Len(t, vuln.From, 0)
		}
		if tt.expectedReach != nil {
			require.NotNil(t, vuln.Reachability)
			require.Equal(t, *vuln.Reachability, *tt.expectedReach)
		} else {
			require.Nil(t, vuln.Reachability)
		}
	}
}

func TestProcessRemediationForFinding(t *testing.T) {
	logger := zerolog.Nop()
	f := testapi.FindingData{
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
					Attributes: &testapi.FixAttributes{},
				},
			},
		},
	}

	t.Run("update package action", func(t *testing.T) {
		vuln := definitions.Vulnerability{
			From: []string{
				"root@1.0.0",
				"foo@1.2.2",
				"bar@1.4.8",
			},
			PackageName: util.Ptr("bar"),
			Version:     "1.4.8",
		}

		upa := testapi.Action{}
		upa.FromUpgradePackageAction(testapi.UpgradePackageAction{
			PackageName: "bar",
			UpgradePaths: []testapi.UpgradePath{
				{
					DependencyPath: []testapi.Package{
						{
							Name:    "root",
							Version: "1.0.0",
						},
						{
							Name:    "foo",
							Version: "1.2.2",
						},
						{
							Name:    "bar",
							Version: "1.4.9",
						},
					},
					IsDrop: false,
				},
			},
			Type: testapi.UpgradePackage,
		})

		upf := f
		upf.Relationships.Fix.Data.Attributes.Actions = &upa

		root := definitions.Vulnerability_UpgradePath_Item{}
		root.FromVulnerabilityUpgradePath1(false)
		path1 := definitions.Vulnerability_UpgradePath_Item{}
		path1.FromVulnerabilityUpgradePath0("foo@1.2.2")
		path2 := definitions.Vulnerability_UpgradePath_Item{}
		path2.FromVulnerabilityUpgradePath0("bar@1.4.9")
		expectedUpgradePath := []definitions.Vulnerability_UpgradePath_Item{root, path1, path2}

		err := transform.ProcessRemediationForFinding(&vuln, &upf, &logger)
		require.NoError(t, err)

		assert.True(t, vuln.IsUpgradable)
		assert.Equal(t, expectedUpgradePath, vuln.UpgradePath)
	})

	t.Run("update package action with drop", func(t *testing.T) {
		vuln := definitions.Vulnerability{
			From: []string{
				"root@1.0.0",
				"foo@1.2.2",
				"bar@1.4.8",
			},
			PackageName: util.Ptr("bar"),
			Version:     "1.4.8",
		}

		upaDrop := testapi.Action{}
		upaDrop.FromUpgradePackageAction(testapi.UpgradePackageAction{
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
							Version: "1.2.3",
						},
					},
					IsDrop: true,
				},
			},
			Type: testapi.UpgradePackage,
		})

		upf := f
		upf.Relationships.Fix.Data.Attributes.Actions = &upaDrop

		root := definitions.Vulnerability_UpgradePath_Item{}
		root.FromVulnerabilityUpgradePath1(false)
		path1 := definitions.Vulnerability_UpgradePath_Item{}
		path1.FromVulnerabilityUpgradePath0("foo@1.2.3")
		expectedUpgradePath := []definitions.Vulnerability_UpgradePath_Item{root, path1}

		err := transform.ProcessRemediationForFinding(&vuln, &upf, &logger)
		require.NoError(t, err)

		assert.True(t, vuln.IsUpgradable)
		assert.Equal(t, expectedUpgradePath, vuln.UpgradePath)
	})

	t.Run("pin package action", func(t *testing.T) {
		vuln := definitions.Vulnerability{
			From: []string{
				"root@1.0.0",
				"foo@1.2.2",
				"bar@1.4.8",
				"baz@4.5.0",
			},
			PackageName: util.Ptr("baz"),
			Version:     "4.5.0",
			FixedIn: util.Ptr([]string{
				"4.5.6",
				"5.0.0",
			}),
		}

		ppa := testapi.Action{}
		ppa.FromPinPackageAction(testapi.PinPackageAction{
			PackageName: "baz",
			PinVersion:  "4.5.6",
			Type:        testapi.PinPackage,
		})

		ppf := f
		ppf.Relationships.Fix.Data.Attributes.Actions = &ppa

		err := transform.ProcessRemediationForFinding(&vuln, &ppf, &logger)
		require.NoError(t, err)

		assert.True(t, *vuln.IsPinnable)
	})
}

func TestProcessLocationForVuln(t *testing.T) {
	packageName := "name"
	packageVersion := "version"
	packageLoc := &testapi.FindingLocation{}
	err := packageLoc.FromPackageLocation(testapi.PackageLocation{
		Package: testapi.Package{
			Name:    packageName,
			Version: packageVersion,
		},
		Type: testapi.PackageLocationTypePackage,
	})
	require.NoError(t, err)

	sourceLoc := &testapi.FindingLocation{}
	err = sourceLoc.FromSourceLocation(testapi.SourceLocation{
		Type: testapi.Source,
	})
	require.NoError(t, err)

	otherLoc := &testapi.FindingLocation{}
	err = otherLoc.FromOtherLocation(testapi.OtherLocation{
		Type: testapi.OtherLocationTypeOther,
	})
	require.NoError(t, err)

	tests := []struct {
		beforeVuln, afterVuln *definitions.Vulnerability
		loc                   *testapi.FindingLocation
	}{
		{&definitions.Vulnerability{}, &definitions.Vulnerability{Name: packageName, Version: packageVersion}, packageLoc},
		{&definitions.Vulnerability{}, &definitions.Vulnerability{}, sourceLoc}, // Source location not supported.
		{&definitions.Vulnerability{}, &definitions.Vulnerability{}, otherLoc},  // Other location not supported.
	}

	for _, tt := range tests {
		logger := zerolog.Nop()
		err := transform.ProcessLocationForVuln(tt.beforeVuln, tt.loc, &logger)
		require.NoError(t, err)
		require.EqualValues(t, tt.beforeVuln, tt.afterVuln)
	}
}

func TestProcessProblemForVuln_License(t *testing.T) {
	// Common license problem data
	now := time.Now()
	licenseProblemBase := testapi.SnykLicenseProblem{
		Id:             "snyk:lic:npm:light-my-request:ISC",
		Source:         testapi.SnykLicense,
		CreatedAt:      now,
		PublishedAt:    now,
		PackageName:    "light-my-request",
		PackageVersion: "5.0.0",
		Severity:       testapi.SeverityLow,
		License:        "ISC",
	}

	// Case 1: Build Ecosystem
	buildEcosystem := testapi.SnykvulndbPackageEcosystem{}
	err := buildEcosystem.FromSnykvulndbBuildPackageEcosystem(testapi.SnykvulndbBuildPackageEcosystem{
		Type:           testapi.Build,
		Language:       "javascript",
		PackageManager: "npm",
	})
	require.NoError(t, err)

	licenseProblemBuild := licenseProblemBase
	licenseProblemBuild.Ecosystem = buildEcosystem

	problemBuild := &testapi.Problem{}
	err = problemBuild.FromSnykLicenseProblem(licenseProblemBuild)
	require.NoError(t, err)

	// Case 2: OS Ecosystem
	osEcosystem := testapi.SnykvulndbPackageEcosystem{}
	err = osEcosystem.FromSnykvulndbOsPackageEcosystem(testapi.SnykvulndbOsPackageEcosystem{
		Type:         testapi.Os,
		Distribution: "alpine",
		OsName:       "linux",
		Release:      "3.16",
	})
	require.NoError(t, err)

	licenseProblemOs := licenseProblemBase
	licenseProblemOs.Ecosystem = osEcosystem

	problemOs := &testapi.Problem{}
	err = problemOs.FromSnykLicenseProblem(licenseProblemOs)
	require.NoError(t, err)

	// Case 3: Other Ecosystem (should be ignored)
	otherEcosystem := testapi.SnykvulndbPackageEcosystem{}
	err = otherEcosystem.FromSnykvulndbOtherPackageEcosystem(testapi.SnykvulndbOtherPackageEcosystem{
		Type: testapi.Other,
	})
	require.NoError(t, err)

	licenseProblemOther := licenseProblemBase
	licenseProblemOther.Ecosystem = otherEcosystem

	problemOther := &testapi.Problem{}
	err = problemOther.FromSnykLicenseProblem(licenseProblemOther)
	require.NoError(t, err)

	tests := []struct {
		name                   string
		vuln                   *definitions.Vulnerability
		problem                *testapi.Problem
		shouldError            bool
		expectedPackageManager *string
		expectedLanguage       *string
	}{
		{
			name:                   "Build ecosystem",
			vuln:                   &definitions.Vulnerability{},
			problem:                problemBuild,
			shouldError:            false,
			expectedPackageManager: util.Ptr("npm"),
			expectedLanguage:       util.Ptr("javascript"),
		},
		{
			name:                   "OS ecosystem",
			vuln:                   &definitions.Vulnerability{},
			problem:                problemOs,
			shouldError:            false,
			expectedPackageManager: util.Ptr("alpine:3.16"),
			expectedLanguage:       nil,
		},
		{
			name:                   "Other ecosystem",
			vuln:                   &definitions.Vulnerability{},
			problem:                problemOther,
			shouldError:            false,
			expectedPackageManager: nil,
			expectedLanguage:       nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := zerolog.Nop()
			err := transform.ProcessProblemForVuln(tt.vuln, tt.problem, &logger)

			if tt.shouldError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.expectedPackageManager, tt.vuln.PackageManager)
			require.Equal(t, tt.expectedLanguage, tt.vuln.Language)
		})
	}
}

func TestFindingToLegacyVulns(t *testing.T) {
	buf, err := os.ReadFile("testdata/multiple-paths-remediation-finding.json")
	require.NoError(t, err)

	var finding testapi.FindingData
	err = json.Unmarshal(buf, &finding)
	require.NoError(t, err)

	logger := zerolog.Nop()
	vulns, err := transform.FindingToLegacyVulns(
		&finding,
		&logger,
	)
	require.NoError(t, err)

	bts, err := json.MarshalIndent(vulns, "", "  ")
	require.NoError(t, err)

	snaps.MatchStandaloneSnapshot(t, string(bts))
}

func TestIsTestResultOk(t *testing.T) {
	tests := []struct {
		name           string
		testResult     testapi.TestResult
		setupMock      func(mock *mocks.MockTestResult)
		expectedResult bool
	}{
		{
			name:           "nil test result should return false",
			testResult:     nil,
			setupMock:      nil,
			expectedResult: false,
		},
		{
			name: "outcome Pass should return true",
			setupMock: func(mock *mocks.MockTestResult) {
				passFail := testapi.Pass
				mock.EXPECT().GetPassFail().Return(&passFail).Times(1)
			},
			expectedResult: true,
		},
		{
			name: "outcome Fail should return false",
			setupMock: func(mock *mocks.MockTestResult) {
				passFail := testapi.Fail
				mock.EXPECT().GetPassFail().Return(&passFail).Times(1)
			},
			expectedResult: false,
		},
		{
			name: "outcome is nil and execution state is not Errored should return true",
			setupMock: func(mock *mocks.MockTestResult) {
				mock.EXPECT().GetPassFail().Return(nil).Times(1)
				mock.EXPECT().GetExecutionState().Return(testapi.Finished).Times(1)
			},
			expectedResult: true,
		},
		{
			name: "outcome is nil and execution state is Errored should return false",
			setupMock: func(mock *mocks.MockTestResult) {
				mock.EXPECT().GetPassFail().Return(nil).Times(1)
				mock.EXPECT().GetExecutionState().Return(testapi.Errored).Times(1)
			},
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var testResult testapi.TestResult

			if tt.setupMock != nil {
				ctrl := gomock.NewController(t)
				defer ctrl.Finish()
				mockTestResult := mocks.NewMockTestResult(ctrl)
				tt.setupMock(mockTestResult)
				testResult = mockTestResult
			} else {
				testResult = tt.testResult
			}

			result := transform.IsTestResultOk(testResult)
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}
