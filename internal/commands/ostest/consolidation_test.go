package ostest_test

import (
	"testing"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/commands/ostest"
	"github.com/snyk/cli-extension-os-flows/internal/presenters"
)

func Test_consolidateFindings(t *testing.T) {
	logger := zerolog.Nop()

	t.Run("preserves highest risk score when consolidating findings", func(t *testing.T) {
		// Create findings with the same Snyk ID but different risk scores
		// The first finding has a lower risk score, the second has the highest
		findings := []testapi.FindingData{
			{
				Attributes: &testapi.FindingAttributes{
					Rating: testapi.Rating{Severity: testapi.SeverityHigh},
					Risk:   testapi.Risk{RiskScore: &testapi.RiskScore{Value: 500}},
					Problems: []testapi.Problem{
						createSnykVulnProblem("SNYK-TEST-001"),
					},
				},
			},
			{
				Attributes: &testapi.FindingAttributes{
					Rating: testapi.Rating{Severity: testapi.SeverityHigh},
					Risk:   testapi.Risk{RiskScore: &testapi.RiskScore{Value: 900}},
					Problems: []testapi.Problem{
						createSnykVulnProblem("SNYK-TEST-001"),
					},
				},
			},
			{
				Attributes: &testapi.FindingAttributes{
					Rating: testapi.Rating{Severity: testapi.SeverityHigh},
					Risk:   testapi.Risk{RiskScore: &testapi.RiskScore{Value: 300}},
					Problems: []testapi.Problem{
						createSnykVulnProblem("SNYK-TEST-001"),
					},
				},
			},
		}

		consolidated := ostest.ConsolidateFindings(findings, &logger)
		require.Len(t, consolidated, 1)

		// The highest risk score (900) should be preserved
		assert.Equal(t, uint16(900), consolidated[0].Attributes.Risk.RiskScore.Value)
	})

	t.Run("preserves highest severity when consolidating findings", func(t *testing.T) {
		// Create findings with the same Snyk ID but different severities
		findings := []testapi.FindingData{
			{
				Attributes: &testapi.FindingAttributes{
					Rating: testapi.Rating{Severity: testapi.SeverityMedium},
					Problems: []testapi.Problem{
						createSnykVulnProblem("SNYK-TEST-002"),
					},
				},
			},
			{
				Attributes: &testapi.FindingAttributes{
					Rating: testapi.Rating{Severity: testapi.SeverityLow},
					Problems: []testapi.Problem{
						createSnykVulnProblem("SNYK-TEST-002"),
					},
				},
			},
			{
				Attributes: &testapi.FindingAttributes{
					Rating: testapi.Rating{Severity: testapi.SeverityCritical},
					Problems: []testapi.Problem{
						createSnykVulnProblem("SNYK-TEST-002"),
					},
				},
			},
		}

		consolidated := ostest.ConsolidateFindings(findings, &logger)
		require.Len(t, consolidated, 1)

		// The highest severity (critical) should be preserved
		assert.Equal(t, testapi.SeverityCritical, consolidated[0].Attributes.Rating.Severity)
	})

	t.Run("preserves highest risk score and severity together", func(t *testing.T) {
		// Create findings where the highest risk score and highest severity come from different findings
		findings := []testapi.FindingData{
			{
				Attributes: &testapi.FindingAttributes{
					Rating: testapi.Rating{Severity: testapi.SeverityHigh},
					Risk:   testapi.Risk{RiskScore: &testapi.RiskScore{Value: 500}},
					Problems: []testapi.Problem{
						createSnykVulnProblem("SNYK-TEST-003"),
					},
				},
			},
			{
				Attributes: &testapi.FindingAttributes{
					Rating: testapi.Rating{Severity: testapi.SeverityMedium},
					Risk:   testapi.Risk{RiskScore: &testapi.RiskScore{Value: 950}},
					Problems: []testapi.Problem{
						createSnykVulnProblem("SNYK-TEST-003"),
					},
				},
			},
			{
				Attributes: &testapi.FindingAttributes{
					Rating: testapi.Rating{Severity: testapi.SeverityCritical},
					Risk:   testapi.Risk{RiskScore: &testapi.RiskScore{Value: 300}},
					Problems: []testapi.Problem{
						createSnykVulnProblem("SNYK-TEST-003"),
					},
				},
			},
		}

		consolidated := ostest.ConsolidateFindings(findings, &logger)
		require.Len(t, consolidated, 1)

		// Both the highest risk score (950) and highest severity (critical) should be preserved
		assert.Equal(t, uint16(950), consolidated[0].Attributes.Risk.RiskScore.Value)
		assert.Equal(t, testapi.SeverityCritical, consolidated[0].Attributes.Rating.Severity)
	})

	t.Run("handles findings without risk scores", func(t *testing.T) {
		findings := []testapi.FindingData{
			{
				// The first finding has no risk score
				Attributes: &testapi.FindingAttributes{
					Rating: testapi.Rating{Severity: testapi.SeverityHigh},
					Risk:   testapi.Risk{RiskScore: nil},
					Problems: []testapi.Problem{
						createSnykVulnProblem("SNYK-TEST-004"),
					},
				},
			},
			{
				Attributes: &testapi.FindingAttributes{
					Rating: testapi.Rating{Severity: testapi.SeverityCritical},
					Risk:   testapi.Risk{RiskScore: &testapi.RiskScore{Value: 800}},
					Problems: []testapi.Problem{
						createSnykVulnProblem("SNYK-TEST-004"),
					},
				},
			},
		}

		consolidated := ostest.ConsolidateFindings(findings, &logger)
		require.Len(t, consolidated, 1)

		// Should preserve the risk score from the second finding
		assert.Equal(t, uint16(800), consolidated[0].Attributes.Risk.RiskScore.Value)
		assert.Equal(t, testapi.SeverityCritical, consolidated[0].Attributes.Rating.Severity)
	})
}

func Test_getIntroducedThroughWithCount(t *testing.T) {
	t.Run("returns single path when only one dependency path exists", func(t *testing.T) {
		finding := testapi.FindingData{
			Attributes: &testapi.FindingAttributes{
				Evidence: []testapi.Evidence{
					createDependencyPathEvidence("package1@1.0.0", "package2@2.0.0"),
				},
			},
		}

		result := presenters.GetIntroducedThroughWithCount(finding)
		assert.Equal(t, "package1@1.0.0 > package2@2.0.0", result)
	})

	t.Run("returns path with count when multiple dependency paths exist", func(t *testing.T) {
		finding := testapi.FindingData{
			Attributes: &testapi.FindingAttributes{
				Evidence: []testapi.Evidence{
					createDependencyPathEvidence("package1@1.0.0", "package2@2.0.0"),
					createDependencyPathEvidence("package3@3.0.0", "package4@4.0.0"),
					createDependencyPathEvidence("package5@5.0.0", "package6@6.0.0"),
				},
			},
		}

		result := presenters.GetIntroducedThroughWithCount(finding)
		assert.Equal(t, "package1@1.0.0 > package2@2.0.0 and 2 other paths", result)
	})

	t.Run("returns path with singular count for exactly 2 paths", func(t *testing.T) {
		finding := testapi.FindingData{
			Attributes: &testapi.FindingAttributes{
				Evidence: []testapi.Evidence{
					createDependencyPathEvidence("package1@1.0.0", "package2@2.0.0"),
					createDependencyPathEvidence("package3@3.0.0", "package4@4.0.0"),
				},
			},
		}

		result := presenters.GetIntroducedThroughWithCount(finding)
		assert.Equal(t, "package1@1.0.0 > package2@2.0.0 and 1 other path", result)
	})

	t.Run("returns empty string when no dependency paths exist", func(t *testing.T) {
		finding := testapi.FindingData{
			Attributes: &testapi.FindingAttributes{
				Evidence: []testapi.Evidence{},
			},
		}

		result := presenters.GetIntroducedThroughWithCount(finding)
		assert.Equal(t, "", result)
	})

	t.Run("returns empty string when attributes are nil", func(t *testing.T) {
		finding := testapi.FindingData{
			Attributes: nil,
		}

		result := presenters.GetIntroducedThroughWithCount(finding)
		assert.Equal(t, "", result)
	})

	t.Run("handles mixed evidence types correctly", func(t *testing.T) {
		finding := testapi.FindingData{
			Attributes: &testapi.FindingAttributes{
				Evidence: []testapi.Evidence{
					createDependencyPathEvidence("package1@1.0.0", "package2@2.0.0"),
					createReachabilityEvidence(),
					createDependencyPathEvidence("package3@3.0.0", "package4@4.0.0"),
				},
			},
		}

		result := presenters.GetIntroducedThroughWithCount(finding)
		assert.Equal(t, "package1@1.0.0 > package2@2.0.0 and 1 other path", result)
	})
}

// Helper functions for creating test data

func createSnykVulnProblem(id string) testapi.Problem {
	var problem testapi.Problem
	err := problem.FromSnykVulnProblem(testapi.SnykVulnProblem{
		Id: id,
	})
	if err != nil {
		panic(err)
	}
	return problem
}

func createDependencyPathEvidence(packages ...string) testapi.Evidence {
	path := make([]testapi.Package, 0, len(packages))
	for _, pkg := range packages {
		// Split package@version format
		name := pkg
		version := ""
		if idx := len(pkg) - 1; idx >= 0 {
			for i := idx; i >= 0; i-- {
				if pkg[i] == '@' {
					name = pkg[:i]
					version = pkg[i+1:]
					break
				}
			}
		}

		path = append(path, testapi.Package{
			Name:    name,
			Version: version,
		})
	}

	var evidence testapi.Evidence
	err := evidence.FromDependencyPathEvidence(testapi.DependencyPathEvidence{
		Path: path,
	})
	if err != nil {
		panic(err)
	}
	return evidence
}

func createReachabilityEvidence() testapi.Evidence {
	var evidence testapi.Evidence
	err := evidence.FromReachabilityEvidence(testapi.ReachabilityEvidence{
		Reachability: testapi.ReachabilityTypeFunction,
	})
	if err != nil {
		panic(err)
	}
	return evidence
}
