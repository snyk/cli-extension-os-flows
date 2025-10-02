package transform

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"

	"github.com/snyk/cli-extension-os-flows/internal/legacy/definitions"
	"github.com/snyk/cli-extension-os-flows/internal/semver/shared"
	"github.com/snyk/cli-extension-os-flows/internal/util"
)

func CalculatePin(vulns []definitions.Vulnerability, semver shared.Runtime) (map[string]definitions.PinRemediation, error) {
	pin := make(map[string]definitions.PinRemediation)
	for _, vuln := range vulns {
		if len(vuln.From) < 2 {
			continue
		}

		key := fmt.Sprintf("%s@%s", vuln.Name, vuln.Version)

		var currentUpgradeToVersion string
		vulnPin, pinExistsForVuln := pin[key]
		if pinExistsForVuln {
			currentUpgradeToVersion = vulnPin.UpgradeTo[len(vuln.Name)+1:]
		}

		if vuln.FixedIn == nil || len(*vuln.FixedIn) == 0 {
			continue
		}

		var sortErr error
		slices.SortStableFunc(*vuln.FixedIn, func(a, b string) int {
			comp, err := semver.Compare(a, b)
			if err != nil {
				sortErr = errors.Join(sortErr, err)
			}
			return comp
		})
		if sortErr != nil {
			return nil, fmt.Errorf("failed to sort fixedIn values: %w", sortErr)
		}

		isTransitive := len(vuln.From) > 2

		var newVersion string
		for _, fixVersion := range *vuln.FixedIn {
			comp, err := semver.Compare(fixVersion, vuln.Version)
			if err != nil {
				return nil, err
			}

			if comp > 0 {
				newVersion = fixVersion
				break
			}
		}

		if newVersion == "" {
			continue
		}

		if !pinExistsForVuln {
			pin[key] = definitions.PinRemediation{
				UpgradeTo:    fmt.Sprintf("%s@%s", vuln.Name, newVersion),
				Vulns:        []string{vuln.Id},
				IsTransitive: isTransitive,
			}
		} else {
			vulnPin.Vulns = append(vulnPin.Vulns, vuln.Id)

			v, err := semver.Compare(newVersion, currentUpgradeToVersion)
			if err != nil {
				return nil, err
			}
			if v > 0 {
				vulnPin.UpgradeTo = fmt.Sprintf("%s@%s", vuln.Name, newVersion)
			}

			if !isTransitive {
				vulnPin.IsTransitive = false
			}

			// vulnPin is a copy of the value from the map,
			// so we need to store it back after modifying it
			pin[key] = vulnPin
		}
	}
	return pin, nil
}

func splitNameAndVersion(path string) (string, string) {
	lastIndx := strings.LastIndex(path, "@")
	return path[:lastIndx], path[lastIndx+1:]
}

func ProcessRemediationForFinding(
	vuln *definitions.Vulnerability,
	finding *testapi.FindingData,
	logger *zerolog.Logger,
) error {
	if finding.Relationships == nil ||
		finding.Relationships.Fix == nil ||
		finding.Relationships.Fix.Data == nil ||
		finding.Relationships.Fix.Data.Attributes == nil ||
		finding.Relationships.Fix.Data.Attributes.Actions == nil {
		return nil
	}

	act := finding.Relationships.Fix.Data.Attributes.Actions
	disc, err := act.Discriminator()
	if err != nil {
		return err
	}

	switch disc {
	case string(testapi.UpgradePackage):
		upa, err := act.AsUpgradePackageAction()
		if err != nil {
			return err
		}
		for _, up := range upa.UpgradePaths {
			rootPath := definitions.Vulnerability_UpgradePath_Item{}
			rootPath.FromVulnerabilityUpgradePath1(false)
			upath := []definitions.Vulnerability_UpgradePath_Item{rootPath}

			match := true
			for i := range up.DependencyPath {
				// The `From` slice is offset by 1, since the upgrade depedency path
				// will not contain information about the root package
				fromName, _ := splitNameAndVersion(vuln.From[i+1])
				if up.DependencyPath[i].Name != fromName {
					match = false
					break
				}
				path := fmt.Sprintf("%s@%s", up.DependencyPath[i].Name, up.DependencyPath[i].Version)
				pth := definitions.Vulnerability_UpgradePath_Item{}
				pth.FromVulnerabilityUpgradePath0(path)
				upath = append(upath, pth)
			}

			if match {
				vuln.IsUpgradable = true
				vuln.UpgradePath = upath
				return nil
			}
		}
		// If we reach this, it means we couldn't match any upgrade path to a "introduced through" path
		logger.Warn().Str("vulnID", vuln.Id).Msg("could not find matching upgrade path for vulnerability")
	case string(testapi.PinPackage):
		ppa, err := act.AsPinPackageAction()
		if err != nil {
			return err
		}
		if ppa.PinVersion == (*vuln.FixedIn)[0] {
			vuln.IsPinnable = util.Ptr(true)
			return nil
		}
	default:
		logger.Warn().Str(logFieldDiscriminator, disc).Msg("unknown remediation type")
	}

	return nil
}

func findUnfixableIssues(vulns []definitions.Vulnerability, pkgManager string) map[string]struct{} {
	unfixableIssues := make(map[string]struct{})
	if pkgManager == "rubygems" {
		for _, vuln := range vulns {
			if !vuln.IsUpgradable && len(vuln.From) > 1 {
				unfixableIssues[fmt.Sprintf("%s:%s", vuln.Id, vuln.From[1])] = struct{}{}
			}
		}
	}
	return unfixableIssues
}

func isVulnUnfixable(vuln definitions.Vulnerability, unfixableIssues map[string]struct{}) bool {
	if len(vuln.From) <= 1 {
		return false
	}
	_, isUnfixable := unfixableIssues[fmt.Sprintf("%s:%s", vuln.Id, vuln.From[1])]
	return isUnfixable
}

func vulnIsUpgradable(vuln definitions.Vulnerability) bool {
	up, err := vuln.UpgradePath[1].AsVulnerabilityUpgradePath0()
	if err != nil {
		panic(err)
	}

	isOutdated := len(vuln.From) > 1 && vuln.From[1] == up
	canFixOutdated := vuln.PackageManager != nil && *vuln.PackageManager == "rubygems"

	vulnIsUpgradable := vuln.IsUpgradable && !isOutdated
	if canFixOutdated {
		vulnIsUpgradable = vuln.IsUpgradable
	}
	return vulnIsUpgradable
}

func canBeUpgraded(vuln definitions.Vulnerability) bool {
	if !vulnIsUpgradable(vuln) {
		return false
	}

	rootUpgrade, err := vuln.UpgradePath[0].AsVulnerabilityUpgradePath1()
	if err != nil {
		panic(err)
	}

	if rootUpgrade {
		return true
	}

	directUpgrade, err := vuln.UpgradePath[0].AsVulnerabilityUpgradePath0()
	if err != nil {
		panic(err)
	}

	if directUpgrade != "" {
		return true
	}

	for i := 1; i < len(vuln.UpgradePath); i++ {
		stringPath, err := vuln.UpgradePath[i].AsVulnerabilityUpgradePath0()
		if err != nil {
			panic(err)
		}

		if len(vuln.From) > i && vuln.From[i] == stringPath {
			return true
		}
	}

	return false
}

// func upgrades(vulns []definitions.Vulnerability, semver shared.Runtime) (map[string]definitions.RemediationUpgradeInfo, error) {
// 	var issues []definitions.Vulnerability
// 	unfixableIssues := findUnfixableIssues(vulns, "")
// 	for _, vuln := range vulns {
// 		if !isVulnUnfixable(vuln, unfixableIssues) &&
// 			len(vuln.UpgradePath) > 1 &&
// 			canBeUpgraded(vuln) {
// 			issues = append(issues, vuln)
// 		}
// 	}
//
// 	slices.SortFunc(issues, func(a, b definitions.Vulnerability) int {
// 		if len(a.From) < 2 {
// 			return -1
// 		}
// 		if len(b.From) < 2 {
// 			return 1
// 		}
//
// 		aName, _ := splitNameAndVersion(a.From[1])
// 		bName, _ := splitNameAndVersion(b.From[1])
// 		compRes := strings.Compare(aName, bName)
// 		if compRes != 0 {
// 			return compRes
// 		}
//
// 		if len(a.UpgradePath) < 2 && len(b.UpgradePath) < 2 {
// 			a.Pu
// 		}
//
// 		if len(b.UpgradePath) < 2 {
// 			return -1
// 		}
//
// 		if len(a.UpgradePath) < 2 {
// 			return 1
// 		}
//
// 		return 0
// 	})
// 	return nil, nil
// }
