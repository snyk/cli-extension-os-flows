package remediation_test

import (
	"testing"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/stretchr/testify/require"

	testapiinline "github.com/snyk/cli-extension-os-flows/internal/util/testapi"
	"github.com/snyk/cli-extension-os-flows/internal/util/testfactories"

	"github.com/snyk/cli-extension-os-flows/internal/remediation"
)

func Test_ShimFindingsToRemediationFindings(t *testing.T) {
	t.Run("finding with no fix", func(t *testing.T) {
		inputFindings := []testapi.FindingData{
			{
				Attributes: &testapi.FindingAttributes{
					Title: "Regular Expression Denial of Service (ReDoS)",
					Rating: testapi.Rating{
						Severity: testapi.SeverityHigh,
					},
					Evidence: []testapi.Evidence{
						testfactories.NewShimDependencyPathEvidence(t, "goof@1.0.0", "@snyk/nodejs-runtime-agent@1.43.0", "acorn@5.7.1"),
					},
					Locations: []testapi.FindingLocation{testfactories.NewShimPackageLocation(t, "acorn@5.7.1")},
					Problems:  []testapi.Problem{testfactories.NewShimVulnProblem(t, "SNYK-JS-ACORN-559469", "js", "npm", []string{"5.7.4", "6.4.1", "7.1.1"})},
				},
			},
		}

		res, err := remediation.ShimFindingsToRemediationFindings(inputFindings)
		require.NoError(t, err)

		require.Equal(t, remediation.Findings{
			{
				Package: newPackage("acorn@5.7.1"),
				Vulnerability: remediation.Vulnerability{
					ID:       "SNYK-JS-ACORN-559469",
					Name:     "Regular Expression Denial of Service (ReDoS)",
					Severity: remediation.SeverityHigh,
				},
				DependencyPaths: []remediation.DependencyPath{
					newDependencyPath("goof@1.0.0", "@snyk/nodejs-runtime-agent@1.43.0", "acorn@5.7.1"),
				},
				FixedInVersions: []string{"5.7.4", "6.4.1", "7.1.1"},
				Fix:             nil,
				PackageManager:  "npm",
			},
		}, res)
	})

	t.Run("finding with license problem (ecosystem without remediation)", func(t *testing.T) {
		inputFindings := []testapi.FindingData{
			{
				Attributes: &testapi.FindingAttributes{
					Title: "BSD-3-Clause",
					Rating: testapi.Rating{
						Severity: testapi.SeverityHigh,
					},
					Evidence: []testapi.Evidence{
						testfactories.NewShimDependencyPathEvidence(t, "goof@1.0.0", "@snyk/nodejs-runtime-agent@1.43.0", "acorn@5.7.1"),
					},
					Locations: []testapi.FindingLocation{testfactories.NewShimPackageLocation(t, "acorn@5.7.1")},
					Problems:  []testapi.Problem{testfactories.NewShimLicenseProblem(t, "npm:lic:foo-bar", "js", "npm")},
				},
			},
		}

		res, err := remediation.ShimFindingsToRemediationFindings(inputFindings)
		require.NoError(t, err)

		require.Equal(t, remediation.Findings{
			{
				Package: newPackage("acorn@5.7.1"),
				Vulnerability: remediation.Vulnerability{
					ID:       "npm:lic:foo-bar",
					Name:     "BSD-3-Clause",
					Severity: remediation.SeverityHigh,
				},
				DependencyPaths: []remediation.DependencyPath{
					newDependencyPath("goof@1.0.0", "@snyk/nodejs-runtime-agent@1.43.0", "acorn@5.7.1"),
				},
				FixedInVersions: []string{},
				Fix:             nil,
				PackageManager:  "npm",
			},
		}, res)
	})

	t.Run("finding with license problem (ecosystem with remediation)", func(t *testing.T) {
		inputFindings := []testapi.FindingData{
			{
				Attributes: &testapi.FindingAttributes{
					Title: "BSD-3-Clause",
					Rating: testapi.Rating{
						Severity: testapi.SeverityHigh,
					},
					Evidence: []testapi.Evidence{
						testfactories.NewShimDependencyPathEvidence(t, "goof@1.0.0", "@snyk/nodejs-runtime-agent@1.43.0", "acorn@5.7.1"),
					},
					Locations: []testapi.FindingLocation{testfactories.NewShimPackageLocation(t, "acorn@5.7.1")},
					Problems:  []testapi.Problem{testfactories.NewShimLicenseProblem(t, "npm:lic:foo-bar", "js", "npm")},
				},
				Relationships: &testapiinline.FindingRelationship{
					Fix: &testapiinline.RelationshipFix{
						Data: &testapiinline.FixData{
							Attributes: &testapi.FixAttributes{
								Outcome: testapi.Unresolved,
							},
						},
					},
				},
			},
		}

		res, err := remediation.ShimFindingsToRemediationFindings(inputFindings)
		require.NoError(t, err)

		require.Equal(t, remediation.Findings{
			{
				Package: newPackage("acorn@5.7.1"),
				Vulnerability: remediation.Vulnerability{
					ID:       "npm:lic:foo-bar",
					Name:     "BSD-3-Clause",
					Severity: remediation.SeverityHigh,
				},
				DependencyPaths: []remediation.DependencyPath{
					newDependencyPath("goof@1.0.0", "@snyk/nodejs-runtime-agent@1.43.0", "acorn@5.7.1"),
				},
				FixedInVersions: []string{},
				Fix:             remediation.UnresolvedFix{},
				PackageManager:  "npm",
			},
		}, res)
	})

	t.Run("finding with single dependency path and pin fix", func(t *testing.T) {
		inputFindings := []testapi.FindingData{
			{
				Attributes: &testapi.FindingAttributes{
					Title: "Regular Expression Denial of Service (ReDoS)",
					Rating: testapi.Rating{
						Severity: testapi.SeverityCritical,
					},
					Evidence: []testapi.Evidence{
						testfactories.NewShimDependencyPathEvidence(t, "goof@1.0.0", "foo@1.2.3", "bar@1.0.0"),
					},
					Locations: []testapi.FindingLocation{testfactories.NewShimPackageLocation(t, "bar@1.0.0")},
					Problems:  []testapi.Problem{testfactories.NewShimVulnProblem(t, "SNYK-PYTHON-BAR-0000", "python", "pip", []string{"1.0.1"})},
				},
				Relationships: testfactories.NewShimPinRelationship(t, "bar@1.0.1"),
			},
		}

		res, err := remediation.ShimFindingsToRemediationFindings(inputFindings)
		require.NoError(t, err)

		require.Equal(t, remediation.Findings{
			{
				Package: newPackage("bar@1.0.0"),
				Vulnerability: remediation.Vulnerability{
					ID:       "SNYK-PYTHON-BAR-0000",
					Name:     "Regular Expression Denial of Service (ReDoS)",
					Severity: remediation.SeverityCritical,
				},
				DependencyPaths: []remediation.DependencyPath{
					newDependencyPath("goof@1.0.0", "foo@1.2.3", "bar@1.0.0"),
				},
				FixedInVersions: []string{"1.0.1"},
				Fix: remediation.NewPinFix(remediation.FullyResolved, remediation.PinAction{
					remediation.Package{
						Name:    "bar",
						Version: "1.0.1",
					},
				}),
				PackageManager: "pip",
			},
		}, res)
	})

	t.Run("finding with single dependency path and upgrade fix with single path (fully resolved) with drop", func(t *testing.T) {
		inputFindings := []testapi.FindingData{
			{
				Attributes: &testapi.FindingAttributes{
					Title: "Regular Expression Denial of Service (ReDoS)",
					Rating: testapi.Rating{
						Severity: testapi.SeverityHigh,
					},
					Evidence: []testapi.Evidence{
						testfactories.NewShimDependencyPathEvidence(t, "goof@1.0.0", "foo-bar@1.0.0", "acorn@5.7.1"),
					},
					Locations: []testapi.FindingLocation{testfactories.NewShimPackageLocation(t, "acorn@5.7.1")},
					Problems:  []testapi.Problem{testfactories.NewShimVulnProblem(t, "SNYK-JS-ACORN-559469", "js", "npm", []string{"5.7.4", "6.4.1", "7.1.1"})},
				},
				Relationships: testfactories.NewShimUpgradeRelationship(
					t,
					testapi.FullyResolved,
					"foo-bar",
					[]testapi.UpgradePath{
						testfactories.NewShimUpgradePath(true, "foo-bar@2.0.0"),
					},
				),
			},
		}

		res, err := remediation.ShimFindingsToRemediationFindings(inputFindings)
		require.NoError(t, err)

		require.Equal(t, remediation.Findings{
			{
				Package: newPackage("acorn@5.7.1"),
				Vulnerability: remediation.Vulnerability{
					ID:       "SNYK-JS-ACORN-559469",
					Name:     "Regular Expression Denial of Service (ReDoS)",
					Severity: remediation.SeverityHigh,
				},
				DependencyPaths: []remediation.DependencyPath{
					newDependencyPath("goof@1.0.0", "foo-bar@1.0.0", "acorn@5.7.1"),
				},
				FixedInVersions: []string{"5.7.4", "6.4.1", "7.1.1"},
				Fix: remediation.NewUpgradeFix(remediation.FullyResolved, remediation.UpgradeAction{
					PackageName: "foo-bar",
					UpgradePaths: []remediation.DependencyPath{
						newDependencyPath("foo-bar@2.0.0"),
					},
				}),
				PackageManager: "npm",
			},
		}, res)
	})

	t.Run("finding with single dependency path and upgrade fix with single path (fully resolved)", func(t *testing.T) {
		inputFindings := []testapi.FindingData{
			{
				Attributes: &testapi.FindingAttributes{
					Title: "Regular Expression Denial of Service (ReDoS)",
					Rating: testapi.Rating{
						Severity: testapi.SeverityHigh,
					},
					Evidence: []testapi.Evidence{
						testfactories.NewShimDependencyPathEvidence(t, "goof@1.0.0", "@snyk/nodejs-runtime-agent@1.43.0", "acorn@5.7.1"),
					},
					Locations: []testapi.FindingLocation{testfactories.NewShimPackageLocation(t, "acorn@5.7.1")},
					Problems:  []testapi.Problem{testfactories.NewShimVulnProblem(t, "SNYK-JS-ACORN-559469", "js", "npm", []string{"5.7.4", "6.4.1", "7.1.1"})},
				},
				Relationships: testfactories.NewShimUpgradeRelationship(
					t,
					testapi.FullyResolved,
					"@snyk/nodejs-runtime-agent",
					[]testapi.UpgradePath{
						testfactories.NewShimUpgradePath(false, "@snyk/nodejs-runtime-agent@1.47.3", "acorn@5.7.4"),
					},
				),
			},
		}
		res, err := remediation.ShimFindingsToRemediationFindings(inputFindings)
		require.NoError(t, err)

		require.Equal(t, remediation.Findings{
			{
				Package: newPackage("acorn@5.7.1"),
				Vulnerability: remediation.Vulnerability{
					ID:       "SNYK-JS-ACORN-559469",
					Name:     "Regular Expression Denial of Service (ReDoS)",
					Severity: remediation.SeverityHigh,
				},
				DependencyPaths: []remediation.DependencyPath{
					newDependencyPath("goof@1.0.0", "@snyk/nodejs-runtime-agent@1.43.0", "acorn@5.7.1"),
				},
				FixedInVersions: []string{"5.7.4", "6.4.1", "7.1.1"},
				Fix: remediation.NewUpgradeFix(remediation.FullyResolved, remediation.UpgradeAction{
					PackageName: "@snyk/nodejs-runtime-agent",
					UpgradePaths: []remediation.DependencyPath{
						newDependencyPath("@snyk/nodejs-runtime-agent@1.47.3", "acorn@5.7.4"),
					},
				}),
				PackageManager: "npm",
			},
		}, res)
	})

	t.Run("finding with multiple dependency paths and upgrade fix with signle path (partially resolved)", func(t *testing.T) {
		inputFindings := []testapi.FindingData{
			{
				Attributes: &testapi.FindingAttributes{
					Title: "Regular Expression Denial of Service (ReDoS)",
					Rating: testapi.Rating{
						Severity: testapi.SeverityHigh,
					},
					Evidence: []testapi.Evidence{
						testfactories.NewShimDependencyPathEvidence(t, "goof@1.0.0", "@snyk/nodejs-runtime-agent@1.43.0", "acorn@5.7.1"),
						testfactories.NewShimDependencyPathEvidence(t, "goof@1.0.0", "foo@1.2.3", "acorn@5.7.1"),
					},
					Locations: []testapi.FindingLocation{testfactories.NewShimPackageLocation(t, "acorn@5.7.1")},
					Problems:  []testapi.Problem{testfactories.NewShimVulnProblem(t, "SNYK-JS-ACORN-559469", "js", "npm", []string{"5.7.4", "6.4.1", "7.1.1"})},
				},
				Relationships: testfactories.NewShimUpgradeRelationship(
					t,
					testapi.PartiallyResolved,
					"@snyk/nodejs-runtime-agent",
					[]testapi.UpgradePath{
						testfactories.NewShimUpgradePath(false, "@snyk/nodejs-runtime-agent@1.47.3", "acorn@5.7.4"),
					},
				),
			},
		}

		res, err := remediation.ShimFindingsToRemediationFindings(inputFindings)
		require.NoError(t, err)

		require.Equal(t, remediation.Findings{
			{
				Package: newPackage("acorn@5.7.1"),
				Vulnerability: remediation.Vulnerability{
					ID:       "SNYK-JS-ACORN-559469",
					Name:     "Regular Expression Denial of Service (ReDoS)",
					Severity: remediation.SeverityHigh,
				},
				DependencyPaths: []remediation.DependencyPath{
					newDependencyPath("goof@1.0.0", "@snyk/nodejs-runtime-agent@1.43.0", "acorn@5.7.1"),
					newDependencyPath("goof@1.0.0", "foo@1.2.3", "acorn@5.7.1"),
				},
				FixedInVersions: []string{"5.7.4", "6.4.1", "7.1.1"},
				Fix: remediation.NewUpgradeFix(remediation.PartiallyResolved, remediation.UpgradeAction{
					PackageName: "@snyk/nodejs-runtime-agent",
					UpgradePaths: []remediation.DependencyPath{
						newDependencyPath("@snyk/nodejs-runtime-agent@1.47.3", "acorn@5.7.4"),
					},
				}),
				PackageManager: "npm",
			},
		}, res)
	})

	t.Run("finding with multiple dependency paths and upgrade fix with multiple paths (fully resolved)", func(t *testing.T) {
		inputFindings := []testapi.FindingData{
			{
				Attributes: &testapi.FindingAttributes{
					Title: "Regular Expression Denial of Service (ReDoS)",
					Rating: testapi.Rating{
						Severity: testapi.SeverityHigh,
					},
					Evidence: []testapi.Evidence{
						testfactories.NewShimDependencyPathEvidence(t, "goof@1.0.0", "@snyk/nodejs-runtime-agent@1.43.0", "acorn@5.7.1"),
						testfactories.NewShimDependencyPathEvidence(t, "goof@1.0.0", "foo@1.2.3", "acorn@5.7.1"),
					},
					Locations: []testapi.FindingLocation{testfactories.NewShimPackageLocation(t, "acorn@5.7.1")},
					Problems:  []testapi.Problem{testfactories.NewShimVulnProblem(t, "SNYK-JS-ACORN-559469", "js", "npm", []string{"5.7.4", "6.4.1", "7.1.1"})},
				},
				Relationships: testfactories.NewShimUpgradeRelationship(
					t,
					testapi.FullyResolved,
					"@snyk/nodejs-runtime-agent",
					[]testapi.UpgradePath{
						testfactories.NewShimUpgradePath(false, "@snyk/nodejs-runtime-agent@1.47.3", "acorn@5.7.4"),
						testfactories.NewShimUpgradePath(false, "foo@1.4.0", "acorn@6.4.1"),
					},
				),
			},
		}

		res, err := remediation.ShimFindingsToRemediationFindings(inputFindings)
		require.NoError(t, err)

		require.Equal(t, remediation.Findings{
			{
				Package: newPackage("acorn@5.7.1"),
				Vulnerability: remediation.Vulnerability{
					ID:       "SNYK-JS-ACORN-559469",
					Name:     "Regular Expression Denial of Service (ReDoS)",
					Severity: remediation.SeverityHigh,
				},
				DependencyPaths: []remediation.DependencyPath{
					newDependencyPath("goof@1.0.0", "@snyk/nodejs-runtime-agent@1.43.0", "acorn@5.7.1"),
					newDependencyPath("goof@1.0.0", "foo@1.2.3", "acorn@5.7.1"),
				},
				FixedInVersions: []string{"5.7.4", "6.4.1", "7.1.1"},
				Fix: remediation.NewUpgradeFix(remediation.FullyResolved, remediation.UpgradeAction{
					PackageName: "@snyk/nodejs-runtime-agent",
					UpgradePaths: []remediation.DependencyPath{
						newDependencyPath("@snyk/nodejs-runtime-agent@1.47.3", "acorn@5.7.4"),
						newDependencyPath("foo@1.4.0", "acorn@6.4.1"),
					},
				}),
				PackageManager: "npm",
			},
		}, res)
	})

	t.Run("finding with suppression gets dropped", func(t *testing.T) {
		inputFindings := []testapi.FindingData{
			{
				Attributes: &testapi.FindingAttributes{
					Title: "Regular Expression Denial of Service (ReDoS)",
					Rating: testapi.Rating{
						Severity: testapi.SeverityHigh,
					},
					Evidence: []testapi.Evidence{
						testfactories.NewShimDependencyPathEvidence(t, "goof@1.0.0", "@snyk/nodejs-runtime-agent@1.43.0", "acorn@5.7.1"),
					},
					Locations: []testapi.FindingLocation{testfactories.NewShimPackageLocation(t, "acorn@5.7.1")},
					Problems:  []testapi.Problem{testfactories.NewShimVulnProblem(t, "SNYK-JS-ACORN-559469", "js", "npm", []string{"5.7.4", "6.4.1", "7.1.1"})},
					Suppression: &testapi.Suppression{
						Status: testapi.SuppressionStatusIgnored,
					},
				},
			},
		}

		res, err := remediation.ShimFindingsToRemediationFindings(inputFindings)
		require.NoError(t, err)

		require.Empty(t, res)
	})
}
