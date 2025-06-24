package transform_test

import (
	"slices"
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
			[]identifierTestProblem{{}},
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
		if tt.cveCount > 0 {
			require.Equal(t, len(tt.vuln.Identifiers.CVE), tt.cveCount)
		}
		if tt.cweCount > 0 {
			require.Equal(t, len(tt.vuln.Identifiers.CWE), tt.cweCount)
		}
	}
}
