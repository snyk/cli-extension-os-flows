package ostest_test

import (
	"context"
	"testing"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	"github.com/snyk/cli-extension-os-flows/internal/commands/ostest"
	"github.com/snyk/cli-extension-os-flows/internal/presenters"
	"github.com/snyk/cli-extension-os-flows/internal/util"
	"github.com/snyk/cli-extension-os-flows/internal/util/testfactories"
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
		ctx := t.Context()
		ctx = cmdctx.WithLogger(ctx, &logger)
		ctx = cmdctx.WithProgressBar(ctx, &nopProgressBar)

		consolidated, err := ostest.ConsolidateFindings(ctx, findings)
		require.NoError(t, err)
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
		ctx := t.Context()
		ctx = cmdctx.WithLogger(ctx, &logger)
		ctx = cmdctx.WithProgressBar(ctx, &nopProgressBar)

		consolidated, err := ostest.ConsolidateFindings(ctx, findings)
		require.NoError(t, err)
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
		ctx := t.Context()
		ctx = cmdctx.WithLogger(ctx, &logger)
		ctx = cmdctx.WithProgressBar(ctx, &nopProgressBar)

		consolidated, err := ostest.ConsolidateFindings(ctx, findings)
		require.NoError(t, err)
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
		ctx := t.Context()
		ctx = cmdctx.WithLogger(ctx, &logger)
		ctx = cmdctx.WithProgressBar(ctx, &nopProgressBar)

		consolidated, err := ostest.ConsolidateFindings(ctx, findings)
		require.NoError(t, err)
		require.Len(t, consolidated, 1)

		// Should preserve the risk score from the second finding
		assert.Equal(t, uint16(800), consolidated[0].Attributes.Risk.RiskScore.Value)
		assert.Equal(t, testapi.SeverityCritical, consolidated[0].Attributes.Rating.Severity)
	})

	t.Run("handles findings with unresolved fix outcome without actions", func(t *testing.T) {
		findings := []testapi.FindingData{
			{
				Attributes: &testapi.FindingAttributes{
					Rating: testapi.Rating{Severity: testapi.SeverityHigh},
					Problems: []testapi.Problem{
						createSnykVulnProblem("SNYK-TEST-005"),
					},
				},
			},
			{
				Attributes: &testapi.FindingAttributes{
					Rating: testapi.Rating{Severity: testapi.SeverityMedium},
					Problems: []testapi.Problem{
						createSnykVulnProblem("SNYK-TEST-005"),
					},
				},
			},
		}

		findings[0].Relationships = testfactories.NewShimUnresolvedRelationship()
		findings[1].Relationships = testfactories.NewShimUnresolvedRelationship()

		ctx := t.Context()
		ctx = cmdctx.WithLogger(ctx, &logger)
		ctx = cmdctx.WithProgressBar(ctx, &nopProgressBar)

		consolidated, err := ostest.ConsolidateFindings(ctx, findings)
		require.NoError(t, err)
		require.Len(t, consolidated, 1)

		require.NotNil(t, consolidated[0].Relationships)
		require.NotNil(t, consolidated[0].Relationships.Fix)
		assert.Equal(t, testapi.Unresolved, consolidated[0].Relationships.Fix.Data.Attributes.Outcome)
		assert.Nil(t, consolidated[0].Relationships.Fix.Data.Attributes.Action)
	})
}

func Test_getIntroducedThroughPaths(t *testing.T) {
	t.Run("returns single path when only one dependency path exists", func(t *testing.T) {
		finding := testapi.FindingData{
			Attributes: &testapi.FindingAttributes{
				Evidence: []testapi.Evidence{
					createDependencyPathEvidence("package1@1.0.0", "package2@2.0.0"),
				},
			},
		}

		result := presenters.GetIntroducedThroughPaths(finding)
		expected := []string{"package1@1.0.0 > package2@2.0.0"}
		assert.Equal(t, expected, result)
	})

	t.Run("returns multiple paths when they exist", func(t *testing.T) {
		finding := testapi.FindingData{
			Attributes: &testapi.FindingAttributes{
				Evidence: []testapi.Evidence{
					createDependencyPathEvidence("package1@1.0.0", "package2@2.0.0"),
					createDependencyPathEvidence("package3@3.0.0", "package4@4.0.0"),
					createDependencyPathEvidence("package5@5.0.0", "package6@6.0.0"),
				},
			},
		}

		result := presenters.GetIntroducedThroughPaths(finding)
		expected := []string{
			"package1@1.0.0 > package2@2.0.0",
			"package3@3.0.0 > package4@4.0.0",
			"package5@5.0.0 > package6@6.0.0",
		}
		assert.Equal(t, expected, result)
	})

	t.Run("returns nil when no dependency paths exist", func(t *testing.T) {
		finding := testapi.FindingData{
			Attributes: &testapi.FindingAttributes{
				Evidence: []testapi.Evidence{},
			},
		}

		result := presenters.GetIntroducedThroughPaths(finding)
		assert.Nil(t, result)
	})

	t.Run("returns nil when attributes are nil", func(t *testing.T) {
		finding := testapi.FindingData{
			Attributes: nil,
		}

		result := presenters.GetIntroducedThroughPaths(finding)
		assert.Nil(t, result)
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

		result := presenters.GetIntroducedThroughPaths(finding)
		expected := []string{
			"package1@1.0.0 > package2@2.0.0",
			"package3@3.0.0 > package4@4.0.0",
		}
		assert.Equal(t, expected, result)
	})
}

func Test_formatPathsCount(t *testing.T) {
	t.Run("returns empty string for zero paths", func(t *testing.T) {
		result := presenters.FormatPathsCount([]string{})
		assert.Equal(t, "", result)
	})

	t.Run("returns empty string for single path", func(t *testing.T) {
		result := presenters.FormatPathsCount([]string{"path1"})
		assert.Equal(t, "", result)
	})

	t.Run("returns singular for two paths", func(t *testing.T) {
		result := presenters.FormatPathsCount([]string{"path1", "path2"})
		assert.Contains(t, result, "1 other path")
		assert.NotContains(t, result, "paths")
	})

	t.Run("returns plural for multiple paths", func(t *testing.T) {
		result := presenters.FormatPathsCount([]string{"path1", "path2", "path3"})
		assert.Contains(t, result, "2 other paths")
	})
}

func Test_consolidateFindingsByComponent(t *testing.T) {
	logger := zerolog.Nop()
	newCtx := func() context.Context {
		ctx := t.Context()
		ctx = cmdctx.WithLogger(ctx, &logger)
		ctx = cmdctx.WithProgressBar(ctx, &nopProgressBar)
		return ctx
	}

	const (
		compA = "pkg:npm/app-a@1.0.0"
		compB = "pkg:npm/app-b@2.0.0"
	)

	findingFor := func(component, snykID string, sev testapi.Severity) testapi.FindingData {
		return testapi.FindingData{
			Attributes: &testapi.FindingAttributes{
				Rating:       testapi.Rating{Severity: sev},
				ComponentKey: util.Ptr(component),
				Problems:     []testapi.Problem{createSnykVulnProblem(snykID)},
			},
		}
	}

	t.Run("reports a shared vulnerability under each component", func(t *testing.T) {
		findings := []testapi.FindingData{
			findingFor(compA, "SNYK-TEST-001", testapi.SeverityHigh),
			findingFor(compB, "SNYK-TEST-001", testapi.SeverityHigh),
		}

		consolidated, err := ostest.ConsolidateFindingsByComponent(newCtx(), findings)
		require.NoError(t, err)
		require.Len(t, consolidated, 2)
		require.NotNil(t, consolidated[0].Attributes.ComponentKey)
		require.NotNil(t, consolidated[1].Attributes.ComponentKey)
		assert.Equal(t, compA, *consolidated[0].Attributes.ComponentKey)
		assert.Equal(t, compB, *consolidated[1].Attributes.ComponentKey)
	})

	t.Run("consolidates duplicates within a component and preserves component order", func(t *testing.T) {
		findings := []testapi.FindingData{
			findingFor(compA, "SNYK-TEST-001", testapi.SeverityHigh),
			findingFor(compB, "SNYK-TEST-002", testapi.SeverityMedium),
			findingFor(compA, "SNYK-TEST-001", testapi.SeverityCritical), // duplicate within compA
		}

		consolidated, err := ostest.ConsolidateFindingsByComponent(newCtx(), findings)
		require.NoError(t, err)
		require.Len(t, consolidated, 2)

		// compA group comes first (first-seen order) with its duplicate merged and highest severity kept.
		require.NotNil(t, consolidated[0].Attributes.ComponentKey)
		assert.Equal(t, compA, *consolidated[0].Attributes.ComponentKey)
		assert.Equal(t, testapi.SeverityCritical, consolidated[0].Attributes.Rating.Severity)

		require.NotNil(t, consolidated[1].Attributes.ComponentKey)
		assert.Equal(t, compB, *consolidated[1].Attributes.ComponentKey)
	})

	t.Run("a single component behaves like global consolidation", func(t *testing.T) {
		findings := []testapi.FindingData{
			findingFor(compA, "SNYK-TEST-001", testapi.SeverityHigh),
			findingFor(compA, "SNYK-TEST-001", testapi.SeverityHigh),
		}

		consolidated, err := ostest.ConsolidateFindingsByComponent(newCtx(), findings)
		require.NoError(t, err)
		require.Len(t, consolidated, 1)
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
