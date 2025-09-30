package transform

import (
	"errors"
	"fmt"
	"slices"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"

	"github.com/snyk/cli-extension-os-flows/internal/legacy/definitions"
	"github.com/snyk/cli-extension-os-flows/internal/semver/shared"
)

func getDepedencyPathEvidence(finding testapi.FindingData) (*testapi.DependencyPathEvidence, error) {
	for _, ev := range finding.Attributes.Evidence {
		disc, err := ev.Discriminator()
		if err != nil {
			return nil, err
		}

		if disc != string(testapi.DependencyPath) {
			continue
		}

		depPath, err := ev.AsDependencyPathEvidence()
		if err != nil {
			return nil, err
		}

		return &depPath, nil
	}
	return nil, fmt.Errorf("no depedency path evidence was found for finding: %s", finding.Id)
}

func getSnykVuln(finding testapi.FindingData) (*testapi.SnykVulnProblem, error) {
	for _, prob := range finding.Attributes.Problems {
		disc, err := prob.Discriminator()
		if err != nil {
			return nil, err
		}

		if disc != string(testapi.SnykVuln) {
			continue
		}

		vuln, err := prob.AsSnykVulnProblem()
		if err != nil {
			return nil, err
		}

		return &vuln, nil
	}
	return nil, nil
}

func CalculatePins(findings []testapi.FindingData, semver shared.Runtime) (map[string]definitions.PinRemediation, error) {
	pin := make(map[string]definitions.PinRemediation)
	for _, finding := range findings {
		depPath, err := getDepedencyPathEvidence(finding)
		if err != nil {
			return nil, err
		}

		if len(depPath.Path) < 2 {
			continue
		}

		vuln, err := getSnykVuln(finding)
		if err != nil {
			return nil, err
		}

		if vuln == nil {
			continue
		}

		key := fmt.Sprintf("%s@%s", vuln.PackageName, vuln.PackageVersion)

		var currentUpgradeToVersion string
		vulnPin, pinExistsForVuln := pin[key]
		if pinExistsForVuln {
			currentUpgradeToVersion = vulnPin.UpgradeTo[len(vuln.PackageName)+1:]
		}

		if len(vuln.InitiallyFixedInVersions) == 0 {
			continue
		}

		var sortErr error
		slices.SortStableFunc(vuln.InitiallyFixedInVersions, func(a, b string) int {
			comp, err := semver.Compare(a, b)
			if err != nil {
				sortErr = errors.Join(sortErr, err)
			}
			return comp
		})
		if sortErr != nil {
			return nil, fmt.Errorf("failed to sort fixedIn values: %w", sortErr)
		}

		var newVersion string
		for _, fixVersion := range vuln.InitiallyFixedInVersions {
			comp, err := semver.Compare(fixVersion, vuln.PackageVersion)
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
				UpgradeTo:    fmt.Sprintf("%s@%s", vuln.PackageName, newVersion),
				Vulns:        []string{vuln.Id},
				IsTransitive: true,
			}
		} else {
			vulnPin.Vulns = append(vulnPin.Vulns, vuln.Id)

			v, err := semver.Compare(newVersion, currentUpgradeToVersion)
			if err != nil {
				return nil, err
			}
			if v > 0 {
				vulnPin.UpgradeTo = fmt.Sprintf("%s@%s", vuln.PackageName, newVersion)
			}

			// vulnPin is a copy of the value from the map,
			// so we need to store it back after modifying it
			pin[key] = vulnPin
		}
	}
	return pin, nil
}
