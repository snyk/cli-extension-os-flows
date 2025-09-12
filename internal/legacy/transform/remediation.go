package transform

import (
	"fmt"
	"strings"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"

	"github.com/snyk/cli-extension-os-flows/internal/legacy/definitions"
	"github.com/snyk/cli-extension-os-flows/internal/util"
)

func getNameFromStringPath(path string) string {
	lastIndx := strings.LastIndex(path, "@")
	return path[:lastIndx]
}

func ProcessRemediationForFinding(
	vuln *definitions.Vulnerability,
	finding *testapi.FindingData,
	logger *zerolog.Logger,
) error {
	if finding.Relationships == nil ||
		finding.Relationships.Remediation == nil ||
		finding.Relationships.Remediation.Data == nil ||
		finding.Relationships.Remediation.Data.Attributes == nil {
		return nil
	}
	for _, act := range finding.Relationships.Remediation.Data.Attributes.Actions {
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
					fromName := getNameFromStringPath(vuln.From[i+1])
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
	}
	return nil
}
