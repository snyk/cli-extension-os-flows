package testfactories

import (
	"testing"

	testapiinline "github.com/snyk/cli-extension-os-flows/internal/util/testapi"

	"github.com/snyk/go-application-framework/pkg/utils"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/stretchr/testify/require"

	legacyUtils "github.com/snyk/cli-extension-os-flows/internal/legacy/utils"
)

// NewShimDependencyPathEvidence creates an instance of testapi.Evidence from a list of packages.
func NewShimDependencyPathEvidence(t *testing.T, pkgs ...string) testapi.Evidence {
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

// NewShimUpgradePath creates a new instance of testapi.UpgradePath.
func NewShimUpgradePath(isDrop bool, pkgs ...string) testapi.UpgradePath {
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

// NewShimPackageLocation creates a new instance of testapi.FindingLocation.
func NewShimPackageLocation(t *testing.T, pkg string) testapi.FindingLocation {
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

// NewShimVulnProblem creates a new instance of testapi.Problem for a vulnerability.
func NewShimVulnProblem(t *testing.T, vulnID, language, pkgManager string, fixedIn []string) testapi.Problem {
	t.Helper()

	prob := testapi.Problem{}
	err := prob.FromSnykVulnProblem(testapi.SnykVulnProblem{
		Id:                       vulnID,
		Ecosystem:                AShimVulnEcosystem(t, language, pkgManager),
		InitiallyFixedInVersions: fixedIn,
		PackageName:              "???",
	})
	require.NoError(t, err)

	return prob
}

// AShimVulnEcosystem creates a new instance of testapi.SnykvulndbPackageEcosystem.
func AShimVulnEcosystem(t *testing.T, language, pkgManager string) testapi.SnykvulndbPackageEcosystem {
	t.Helper()

	ecosystem := testapi.SnykvulndbPackageEcosystem{}
	err := ecosystem.FromSnykvulndbBuildPackageEcosystem(testapi.SnykvulndbBuildPackageEcosystem{
		Language:       language,
		PackageManager: pkgManager,
		Type:           testapi.Build,
	})
	require.NoError(t, err)
	return ecosystem
}

func apply[T any](overrides []func(*T), defaults T) T {
	for _, override := range overrides {
		override(&defaults)
	}
	return defaults
}

// NewShimLicenseProblem creates a new instance of testapi.Problem for a license issue.
func NewShimLicenseProblem(t *testing.T, licID, language, pkgManager string) testapi.Problem {
	t.Helper()

	ecosystem := testapi.SnykvulndbPackageEcosystem{}
	err := ecosystem.FromSnykvulndbBuildPackageEcosystem(testapi.SnykvulndbBuildPackageEcosystem{
		Language:       language,
		PackageManager: pkgManager,
		Type:           testapi.Build,
	})
	require.NoError(t, err)
	prob := testapi.Problem{}
	err = prob.FromSnykLicenseProblem(testapi.SnykLicenseProblem{
		Id:        licID,
		Ecosystem: ecosystem,
	})
	require.NoError(t, err)

	return prob
}

// NewShimPolicyRelationship creates a new instance of testapiinline.PolicyRelationship.
func NewShimPolicyRelationship(overrides ...func(rel *testapiinline.PolicyRelationship)) *testapiinline.PolicyRelationship {
	return utils.Ptr(apply(overrides, testapiinline.PolicyRelationship{
		Data: &testapiinline.PolicyRelationshipData{
			Attributes: &testapi.PolicyAttributes{},
		},
	}))
}

// NewAppliedPolicyFromIgnore creates a new instance of testapi.AppliedPolicy from an ignore.
func NewAppliedPolicyFromIgnore(t *testing.T, overrides ...func(ignore *testapi.Ignore)) testapi.AppliedPolicy {
	t.Helper()

	ignore := apply(overrides, testapi.Ignore{})

	appliedPolicy := testapi.AppliedPolicy{}
	err := appliedPolicy.FromIgnore(ignore)
	require.NoError(t, err)
	return appliedPolicy
}

// NewShimUpgradeRelationship creates a new instance of testapiinline.FindingRelationship with an upgrade fix.
func NewShimUpgradeRelationship(
	t *testing.T,
	outcome testapi.FixAppliedOutcome,
	pkgName string,
	upgradePaths []testapi.UpgradePath,
) *testapiinline.FindingRelationship {
	t.Helper()

	act := testapi.Action{}
	err := act.FromUpgradePackageAction(testapi.UpgradePackageAction{
		PackageName:  pkgName,
		UpgradePaths: upgradePaths,
		Type:         testapi.UpgradePackage,
	})
	require.NoError(t, err)

	return &testapiinline.FindingRelationship{
		Fix: &testapiinline.RelationshipFix{
			Data: &testapiinline.FixData{
				Attributes: &testapi.FixAttributes{
					Outcome: outcome,
					Actions: &act,
				},
			},
		},
	}
}

// NewShimPinRelationship creates a FindingRelationship with a pin fix.
func NewShimPinRelationship(t *testing.T, pkg string) *testapiinline.FindingRelationship {
	t.Helper()

	act := testapi.Action{}
	name, version := legacyUtils.SplitNameAndVersion(pkg)
	err := act.FromPinPackageAction(testapi.PinPackageAction{
		PackageName: name,
		PinVersion:  version,
		Type:        testapi.PinPackage,
	})
	require.NoError(t, err)

	return &testapiinline.FindingRelationship{
		Fix: &testapiinline.RelationshipFix{
			Data: &testapiinline.FixData{
				Attributes: &testapi.FixAttributes{
					Outcome: testapi.FullyResolved,
					Actions: &act,
				},
			},
		},
	}
}
