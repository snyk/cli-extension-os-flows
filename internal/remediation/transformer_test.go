//nolint:revive // Interferes with inline types from testapi.
package remediation_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/stretchr/testify/require"

	legacyUtils "github.com/snyk/cli-extension-os-flows/internal/legacy/utils"
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
						newShimDependencyPathEvidence(t, "goof@1.0.0", "@snyk/nodejs-runtime-agent@1.43.0", "acorn@5.7.1"),
					},
					Locations: []testapi.FindingLocation{newShimPackageLocation(t, "acorn@5.7.1")},
					Problems:  []testapi.Problem{newShimVulnProblem(t, "SNYK-JS-ACORN-559469", "js", "npm", []string{"5.7.4", "6.4.1", "7.1.1"})},
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
				Fix:             remediation.UnresolvedFix{},
				PackageManager:  "npm",
			},
		}, res)
	})

	t.Run("finding with license problem", func(t *testing.T) {
		inputFindings := []testapi.FindingData{
			{
				Attributes: &testapi.FindingAttributes{
					Title: "BSD-3-Clause",
					Rating: testapi.Rating{
						Severity: testapi.SeverityHigh,
					},
					Evidence: []testapi.Evidence{
						newShimDependencyPathEvidence(t, "goof@1.0.0", "@snyk/nodejs-runtime-agent@1.43.0", "acorn@5.7.1"),
					},
					Locations: []testapi.FindingLocation{newShimPackageLocation(t, "acorn@5.7.1")},
					Problems:  []testapi.Problem{newShimLicenseProblem(t, "npm:lic:foo-bar", "js", "npm")},
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
						newShimDependencyPathEvidence(t, "goof@1.0.0", "foo@1.2.3", "bar@1.0.0"),
					},
					Locations: []testapi.FindingLocation{newShimPackageLocation(t, "bar@1.0.0")},
					Problems:  []testapi.Problem{newShimVulnProblem(t, "SNYK-PYTHON-BAR-0000", "python", "pip", []string{"1.0.1"})},
				},
				Relationships: newShimPinRelationship(t, "bar@1.0.1"),
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
						newShimDependencyPathEvidence(t, "goof@1.0.0", "foo-bar@1.0.0", "acorn@5.7.1"),
					},
					Locations: []testapi.FindingLocation{newShimPackageLocation(t, "acorn@5.7.1")},
					Problems:  []testapi.Problem{newShimVulnProblem(t, "SNYK-JS-ACORN-559469", "js", "npm", []string{"5.7.4", "6.4.1", "7.1.1"})},
				},
				Relationships: newShimUpgradeRelationship(
					t,
					testapi.FullyResolved,
					"foo-bar",
					[]testapi.UpgradePath{
						newShimUpgradePath(true, "foo-bar@2.0.0"),
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
						newShimDependencyPathEvidence(t, "goof@1.0.0", "@snyk/nodejs-runtime-agent@1.43.0", "acorn@5.7.1"),
					},
					Locations: []testapi.FindingLocation{newShimPackageLocation(t, "acorn@5.7.1")},
					Problems:  []testapi.Problem{newShimVulnProblem(t, "SNYK-JS-ACORN-559469", "js", "npm", []string{"5.7.4", "6.4.1", "7.1.1"})},
				},
				Relationships: newShimUpgradeRelationship(
					t,
					testapi.FullyResolved,
					"@snyk/nodejs-runtime-agent",
					[]testapi.UpgradePath{
						newShimUpgradePath(false, "@snyk/nodejs-runtime-agent@1.47.3", "acorn@5.7.4"),
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
						newShimDependencyPathEvidence(t, "goof@1.0.0", "@snyk/nodejs-runtime-agent@1.43.0", "acorn@5.7.1"),
						newShimDependencyPathEvidence(t, "goof@1.0.0", "foo@1.2.3", "acorn@5.7.1"),
					},
					Locations: []testapi.FindingLocation{newShimPackageLocation(t, "acorn@5.7.1")},
					Problems:  []testapi.Problem{newShimVulnProblem(t, "SNYK-JS-ACORN-559469", "js", "npm", []string{"5.7.4", "6.4.1", "7.1.1"})},
				},
				Relationships: newShimUpgradeRelationship(
					t,
					testapi.PartiallyResolved,
					"@snyk/nodejs-runtime-agent",
					[]testapi.UpgradePath{
						newShimUpgradePath(false, "@snyk/nodejs-runtime-agent@1.47.3", "acorn@5.7.4"),
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
						newShimDependencyPathEvidence(t, "goof@1.0.0", "@snyk/nodejs-runtime-agent@1.43.0", "acorn@5.7.1"),
						newShimDependencyPathEvidence(t, "goof@1.0.0", "foo@1.2.3", "acorn@5.7.1"),
					},
					Locations: []testapi.FindingLocation{newShimPackageLocation(t, "acorn@5.7.1")},
					Problems:  []testapi.Problem{newShimVulnProblem(t, "SNYK-JS-ACORN-559469", "js", "npm", []string{"5.7.4", "6.4.1", "7.1.1"})},
				},
				Relationships: newShimUpgradeRelationship(
					t,
					testapi.FullyResolved,
					"@snyk/nodejs-runtime-agent",
					[]testapi.UpgradePath{
						newShimUpgradePath(false, "@snyk/nodejs-runtime-agent@1.47.3", "acorn@5.7.4"),
						newShimUpgradePath(false, "foo@1.4.0", "acorn@6.4.1"),
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
}

func newShimDependencyPathEvidence(t *testing.T, pkgs ...string) testapi.Evidence {
	t.Helper()

	ev := testapi.Evidence{}
	path := make([]testapi.Package, 0, len(pkgs))
	for _, pkg := range pkgs {
		name, version := legacyUtils.SplitNameAndVersion(pkg)
		path = append(path, testapi.Package{
			Name:    name,
			Version: version,
		})
	}
	err := ev.FromDependencyPathEvidence(testapi.DependencyPathEvidence{
		Path:   path,
		Source: testapi.DependencyPath,
	})
	require.NoError(t, err)

	return ev
}

func newShimUpgradePath(isDrop bool, pkgs ...string) testapi.UpgradePath {
	uPath := make([]testapi.Package, 0, len(pkgs))
	for _, pkg := range pkgs {
		name, version := legacyUtils.SplitNameAndVersion(pkg)
		uPath = append(uPath, testapi.Package{Name: name, Version: version})
	}
	return testapi.UpgradePath{
		DependencyPath: uPath,
		IsDrop:         isDrop,
	}
}

func newShimPackageLocation(t *testing.T, pkg string) testapi.FindingLocation {
	t.Helper()

	loc := testapi.FindingLocation{}
	name, version := legacyUtils.SplitNameAndVersion(pkg)
	err := loc.FromPackageLocation(testapi.PackageLocation{
		Package: testapi.Package{
			Name:    name,
			Version: version,
		},
		Type: testapi.PackageLocationTypePackage,
	})
	require.NoError(t, err)

	return loc
}

func newShimVulnProblem(t *testing.T, vulnID, language, pkgManager string, fixedIn []string) testapi.Problem {
	t.Helper()

	ecosystem := testapi.SnykvulndbPackageEcosystem{}
	err := ecosystem.FromSnykvulndbBuildPackageEcosystem(testapi.SnykvulndbBuildPackageEcosystem{
		Language:       language,
		PackageManager: pkgManager,
		Type:           testapi.Build,
	})
	require.NoError(t, err)
	prob := testapi.Problem{}
	prob.FromSnykVulnProblem(testapi.SnykVulnProblem{
		Id:                       vulnID,
		Ecosystem:                ecosystem,
		InitiallyFixedInVersions: fixedIn,
	})

	return prob
}

func newShimLicenseProblem(t *testing.T, licID, language, pkgManager string) testapi.Problem {
	t.Helper()

	ecosystem := testapi.SnykvulndbPackageEcosystem{}
	err := ecosystem.FromSnykvulndbBuildPackageEcosystem(testapi.SnykvulndbBuildPackageEcosystem{
		Language:       language,
		PackageManager: pkgManager,
		Type:           testapi.Build,
	})
	require.NoError(t, err)
	prob := testapi.Problem{}
	prob.FromSnykLicenseProblem(testapi.SnykLicenseProblem{
		Id:        licID,
		Ecosystem: ecosystem,
	})

	return prob
}

type FixData = struct {
	Attributes *testapi.FixAttributes "json:\"attributes,omitempty\""
	Id         uuid.UUID              "json:\"id\""
	Type       string                 "json:\"type\""
}

type RelationshipFix = struct {
	Data *FixData "json:\"data,omitempty\""
}

type FindingRelationship = struct {
	Asset *struct {
		Data *struct {
			Id   uuid.UUID "json:\"id\""
			Type string    "json:\"type\""
		} "json:\"data,omitempty\""
		Links testapi.IoSnykApiCommonRelatedLink "json:\"links\""
		Meta  *testapi.IoSnykApiCommonMeta       "json:\"meta,omitempty\""
	} "json:\"asset,omitempty\""
	Fix *RelationshipFix "json:\"fix,omitempty\""
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
}

func newShimPinRelationship(t *testing.T, pkg string) *FindingRelationship {
	t.Helper()

	act := testapi.Action{}
	name, version := legacyUtils.SplitNameAndVersion(pkg)
	err := act.FromPinPackageAction(testapi.PinPackageAction{
		PackageName: name,
		PinVersion:  version,
		Type:        testapi.PinPackage,
	})
	require.NoError(t, err)

	return &FindingRelationship{
		Fix: &RelationshipFix{
			Data: &FixData{
				Attributes: &testapi.FixAttributes{
					Outcome: testapi.FullyResolved,
					Actions: &act,
				},
			},
		},
	}
}

func newShimUpgradeRelationship(t *testing.T, outcome testapi.FixAppliedOutcome, pkgName string, upgradePaths []testapi.UpgradePath) *FindingRelationship {
	t.Helper()

	act := testapi.Action{}
	err := act.FromUpgradePackageAction(testapi.UpgradePackageAction{
		PackageName:  pkgName,
		UpgradePaths: upgradePaths,
		Type:         testapi.UpgradePackage,
	})
	require.NoError(t, err)

	return &FindingRelationship{
		Fix: &RelationshipFix{
			Data: &FixData{
				Attributes: &testapi.FixAttributes{
					Outcome: outcome,
					Actions: &act,
				},
			},
		},
	}
}
