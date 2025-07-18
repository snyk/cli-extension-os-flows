package transform_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/legacy/definitions"
	"github.com/snyk/cli-extension-os-flows/internal/legacy/transform"
)

type identifierTestProblem struct {
	disc        string
	problem     *testapi.Problem
	shouldError bool
}

func TestAddingOfIdentifiers(t *testing.T) {
	cveProblem := &testapi.Problem{}
	err := cveProblem.FromCveProblem(testapi.CveProblem{Id: "cve-problem-id", Source: testapi.Cve})
	require.NoError(t, err)

	cweProblem := &testapi.Problem{}
	err = cweProblem.FromCweProblem(testapi.CweProblem{Id: "cwe-problem-id", Source: testapi.Cwe})
	require.NoError(t, err)

	tests := []struct {
		vuln               *definitions.Vulnerability
		probs              []identifierTestProblem
		cveCount, cweCount int
	}{
		{
			&definitions.Vulnerability{},
			[]identifierTestProblem{{string(testapi.Cve), cveProblem, false}},
			1, 0,
		},
		{
			&definitions.Vulnerability{},
			[]identifierTestProblem{{string(testapi.Cwe), cweProblem, false}},
			0, 1,
		},
		{
			&definitions.Vulnerability{},
			[]identifierTestProblem{},
			0, 0,
		},
		{
			&definitions.Vulnerability{},
			[]identifierTestProblem{
				{string(testapi.Cwe), cweProblem, false},
				{string(testapi.Cve), cveProblem, false},
				{string(testapi.Cwe), cveProblem, true}, // wrong discriminator.
				{string(testapi.Cve), cweProblem, true}, // wrong discriminator.
			},
			1, 1,
		},
	}

	for _, tt := range tests {
		for _, prob := range tt.probs {
			switch prob.disc {
			case string(testapi.Cve):
				err := transform.AddCVEIdentifier(tt.vuln, prob.problem)
				if prob.shouldError {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
					cveP, err := prob.problem.AsCveProblem()
					require.NoError(t, err)
					require.Equal(t, slices.Contains(tt.vuln.Identifiers.CVE, cveP.Id), true)
				}
			case string(testapi.Cwe):
				err := transform.AddCWEIdentifier(tt.vuln, prob.problem)
				if prob.shouldError {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
					cweP, err := prob.problem.AsCweProblem()
					require.NoError(t, err)
					require.Equal(t, slices.Contains(tt.vuln.Identifiers.CWE, cweP.Id), true)
				}
			}
		}
		if len(tt.probs) > 0 {
			require.Equal(t, len(tt.vuln.Identifiers.CVE), tt.cveCount)
			require.Equal(t, len(tt.vuln.Identifiers.CWE), tt.cweCount)
		} else {
			require.Nil(t, tt.vuln.Identifiers)
		}
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

	tests := []struct {
		ev        *testapi.Evidence
		results   []string
		shouldErr bool
	}{
		{&testapi.Evidence{}, nil, true},
		{emptyDepPathEv, nil, false},
		{depPathEv, testDepList, false},
		{execFlowEv, nil, false},  // Exec flow not yet supported.
		{otherFlowEv, nil, false}, // Other flow not yet supported.
	}

	for _, tt := range tests {
		res, err := transform.ProcessEvidenceForFinding(tt.ev)
		if tt.shouldErr {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
		}
		require.EqualValues(t, res, tt.results)
	}
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
		err := transform.ProcessLocationForVuln(tt.beforeVuln, tt.loc)
		require.NoError(t, err)
		require.EqualValues(t, tt.beforeVuln, tt.afterVuln)
	}
}
