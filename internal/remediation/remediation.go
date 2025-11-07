package remediation

import (
	"fmt"

	"github.com/snyk/cli-extension-os-flows/internal/legacy/utils"
	"github.com/snyk/cli-extension-os-flows/pkg/semver"
)

// FindingsToRemediationSummary will compute a remediation summary based on the provided findings.
func FindingsToRemediationSummary(findings Findings) (Summary, error) {
	pins, err := calculatePins(findings)
	if err != nil {
		return Summary{}, err
	}

	upgrades, upgradesUnresolved, err := calculateUpgrades(findings)
	if err != nil {
		return Summary{}, err
	}

	unresolved := calculateUnresolved(findings)

	return Summary{
		Pins:       pins,
		Upgrades:   upgrades,
		Unresolved: append(unresolved, upgradesUnresolved...),
	}, err
}

func calculateUnresolved(findings Findings) (unresolved []*VulnerabilityInPackage) {
	for finding := range findings.WithUnresolvedFixes() {
		unresolved = append(unresolved, newVulnerabilityInPackage(finding))
	}
	return unresolved
}

func calculateUpgrades(findings Findings) (upgrades []*Upgrade, unresolved []*VulnerabilityInPackage, err error) {
	upgradeMap := make(map[string]*Upgrade)
	for finding, fix := range findings.WithUpgradeFixes() {
		matchingPaths := getMatchingPaths(finding, fix)

		upgradablePaths := matchingPaths.upgradablePaths
		for i := range upgradablePaths.upgradePath {
			vulnerabilityInPackage := newVulnerabilityInPackage(finding)
			vulnerabilityInPackage.IntroducedThrough = upgradablePaths.dependencyPath

			from := upgradablePaths.dependencyPath[i][1]
			to := upgradablePaths.upgradePath[i][1]
			key := utils.JoinNameAndVersion(from.Name, from.Version)
			existingUpgrade, exists := upgradeMap[key]
			if exists {
				maxVersion, err := getMaxVersion(finding.PackageManager, existingUpgrade.To.Version, to.Version)
				if err != nil {
					return nil, nil, err
				}

				existingUpgrade.To.Version = maxVersion
				existingUpgrade.Fixes = append(existingUpgrade.Fixes, vulnerabilityInPackage)

				upgradeMap[key] = existingUpgrade
			} else {
				upgradeMap[key] = &Upgrade{
					From:  from,
					To:    to,
					Fixes: []*VulnerabilityInPackage{vulnerabilityInPackage},
				}
			}
		}

		// If the fix fully resolves all issues in all dependency paths, then there is
		// no need to report any non-upgradable paths (see below).
		// This is an edgecase in the python ecosystem, where technically there might be
		// unresolved dependency paths, but a pin fixes all vulnerable paths at once.
		if fix.outcome == FullyResolved {
			continue
		}

		if len(matchingPaths.nonUpgradablePaths) > 0 {
			vulnerabilityInPackage := newVulnerabilityInPackage(finding)
			vulnerabilityInPackage.IntroducedThrough = matchingPaths.nonUpgradablePaths
			unresolved = append(unresolved, vulnerabilityInPackage)
		}
	}

	for _, upgrade := range upgradeMap {
		upgrades = append(upgrades, upgrade)
	}

	return upgrades, unresolved, nil
}

/*
*
Returns equally ordered arrays of original dependencyPaths and their upgrade counterparts.

For those upgrades/dep paths that don't have a counterpart, no entries will be found.
*/
type paths struct {
	upgradablePaths    upgradablePaths
	nonUpgradablePaths []DependencyPath
}

type upgradablePaths struct {
	dependencyPath []DependencyPath
	upgradePath    []DependencyPath
}

func getMatchingPaths(finding *Finding, fix UpgradeFix) paths {
	var upgradePaths []DependencyPath
	var dependencyPaths []DependencyPath
	var nonUpgradablePaths []DependencyPath

	for _, depPath := range finding.DependencyPaths {
		found := false
		for _, upath := range fix.UpgradeAction.UpgradePaths {
			if !isMatchingUpgradePath(upath, depPath) {
				continue
			}
			found = true
			upgradePaths = append(upgradePaths, upath)
			dependencyPaths = append(dependencyPaths, depPath)
			break
		}
		if !found {
			nonUpgradablePaths = append(nonUpgradablePaths, depPath)
		}
	}
	return paths{
		upgradablePaths: upgradablePaths{
			dependencyPath: dependencyPaths,
			upgradePath:    upgradePaths,
		},
		nonUpgradablePaths: nonUpgradablePaths,
	}
}

func calculatePins(findings Findings) ([]*Upgrade, error) {
	var output []*Upgrade
	pinMap := make(map[string]*[]*Upgrade)
	for finding, fix := range findings.WithPinFixes() {
		vulnerablePackage := finding.Package
		key := finding.Package.Name

		// We'll be grouping by package name
		upgrade, upgradeExists := pinMap[key]

		if upgradeExists {
			highestVersion, err := getMaxVersion(finding.PackageManager, (*upgrade)[0].To.Version, fix.PinAction.Package.Version)
			if err != nil {
				return nil, err
			}

			// As we process individual pins, we'll get the highest version of a given package across vulns & package version
			// Goal is to obtain a single pin that fixes as many problems as possible
			versionAlreadyExists := false
			for _, u := range *upgrade {
				u.To.Version = highestVersion
				if u.From.Version == finding.Package.Version {
					u.Fixes = append(u.Fixes, newVulnerabilityInPackage(finding))
					versionAlreadyExists = true
					break
				}
			}
			if !versionAlreadyExists {
				*upgrade = append(*upgrade, &Upgrade{
					From:  vulnerablePackage,
					To:    fix.PinAction.Package,
					Fixes: []*VulnerabilityInPackage{newVulnerabilityInPackage(finding)},
				})
			}
		} else {
			pinMap[key] = &[]*Upgrade{{
				From:  vulnerablePackage,
				To:    fix.PinAction.Package,
				Fixes: []*VulnerabilityInPackage{newVulnerabilityInPackage(finding)},
			}}
		}
	}

	for _, versionGroupedPins := range pinMap {
		output = append(output, *versionGroupedPins...)
	}
	return output, nil
}

func newVulnerabilityInPackage(finding *Finding) *VulnerabilityInPackage {
	return &VulnerabilityInPackage{
		FixedInVersions:   finding.FixedInVersions,
		VulnerablePackage: finding.Package,
		Vulnerability:     finding.Vulnerability,
		IntroducedThrough: finding.DependencyPaths,
	}
}

func isMatchingUpgradePath(upath, depPath DependencyPath) bool {
	for i, uDep := range upath {
		if uDep.Name != depPath[i].Name {
			return false
		}
	}
	return true
}

func getMaxVersion(packageManager PackageManager, v1, v2 string) (string, error) {
	semverResolver, err := semver.GetSemver(string(packageManager))
	if err != nil {
		return "", fmt.Errorf("failed to resolve semver library: %w", err)
	}
	var version string
	compare, err := semverResolver.Compare(v1, v2)
	if err != nil {
		return "", fmt.Errorf("failed to compare package versions: %w", err)
	}
	if compare >= 0 {
		version = v1
	} else {
		version = v2
	}
	return version, nil
}
