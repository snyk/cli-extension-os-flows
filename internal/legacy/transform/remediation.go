package transform

import (
	"fmt"
	"slices"
	"strings"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"

	"github.com/snyk/cli-extension-os-flows/internal/legacy/definitions"
	legacyUtils "github.com/snyk/cli-extension-os-flows/internal/legacy/utils"
	"github.com/snyk/cli-extension-os-flows/internal/remediation"
	"github.com/snyk/cli-extension-os-flows/internal/util"
)

// ProcessRemediationForFinding will enhance the vulnerability data with remediation information from the finding's fix.
func ProcessRemediationForFinding(
	vuln *definitions.Vulnerability,
	finding *testapi.FindingData,
	logger *zerolog.Logger,
) error {
	if finding.Relationships == nil ||
		finding.Relationships.Fix == nil ||
		finding.Relationships.Fix.Data == nil ||
		finding.Relationships.Fix.Data.Attributes == nil ||
		finding.Relationships.Fix.Data.Attributes.Action == nil {
		return nil
	}

	act := finding.Relationships.Fix.Data.Attributes.Action
	disc, err := act.Discriminator()
	if err != nil {
		return fmt.Errorf("failed to get action discriminator: %w", err)
	}

	switch disc {
	case string(testapi.UpgradePackageAdviceFormatUpgradePackageAdvice):
		err := processUpgradeAction(vuln, act, logger)
		if err != nil {
			return fmt.Errorf("failed to process upgrade action: %w", err)
		}
	case string(testapi.PinPackageAdviceFormatPinPackageAdvice):
		err := processPinAction(vuln, act)
		if err != nil {
			return fmt.Errorf("failed to process pin action: %w", err)
		}
	default:
		logger.Warn().Str(logFieldDiscriminator, disc).Msg("unknown remediation type")
	}

	return nil
}

func processUpgradeAction(vuln *definitions.Vulnerability, act *testapi.FixAction, logger *zerolog.Logger) error {
	upa, err := act.AsUpgradePackageAdvice()
	if err != nil {
		return fmt.Errorf("failed to convert action to upgrade action: %w", err)
	}

	for _, up := range upa.UpgradePaths {
		rootPath := definitions.Vulnerability_UpgradePath_Item{}
		err := rootPath.FromVulnerabilityUpgradePath1(false)
		if err != nil {
			return fmt.Errorf("failed to convert bool to upgrade path: %w", err)
		}
		upath := []definitions.Vulnerability_UpgradePath_Item{rootPath}

		match := true
		for i := 1; i < len(up.DependencyPath); i++ {
			fromName, _ := legacyUtils.SplitNameAndVersion(vuln.From[i])
			if up.DependencyPath[i].Name != fromName {
				match = false
				break
			}
			path := fmt.Sprintf("%s@%s", up.DependencyPath[i].Name, up.DependencyPath[i].Version)
			pth := definitions.Vulnerability_UpgradePath_Item{}
			err := pth.FromVulnerabilityUpgradePath0(path)
			if err != nil {
				return fmt.Errorf("failed to convert string path to upgrade path: %w", err)
			}
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
	return nil
}

func processPinAction(vuln *definitions.Vulnerability, act *testapi.FixAction) error {
	ppa, err := act.AsPinPackageAdvice()
	if err != nil {
		return fmt.Errorf("failed to convert action to pin action: %w", err)
	}

	idx := slices.Index(*vuln.FixedIn, ppa.PinVersion)
	if idx != -1 {
		vuln.IsPinnable = util.Ptr(true)
		return nil
	}

	return nil
}

func setUnresolved(summary *definitions.Remediation, remSummary remediation.Summary, legacyVulns []definitions.Vulnerability) error {
	rawVulnsMap := make(map[string]*definitions.Vulnerability)
	// We only construct the map if we have unresolved issues
	// as it will only be used for lookups in that scenario
	if len(remSummary.Unresolved) > 0 {
		for i := range legacyVulns {
			vuln := &legacyVulns[i]
			key := getVulnKeyByPath(vuln.Id, vuln.From)
			rawVulnsMap[key] = vuln
		}
	}

	for _, unresolved := range remSummary.Unresolved {
		for _, introducedThrough := range unresolved.IntroducedThrough {
			path := make([]string, 0, len(introducedThrough))
			for _, pkg := range introducedThrough {
				path = append(path, legacyUtils.JoinNameAndVersion(pkg.Name, pkg.Version))
			}
			key := getVulnKeyByPath(string(unresolved.Vulnerability.ID), path)
			rawVuln, exists := rawVulnsMap[key]
			if !exists {
				return fmt.Errorf("vulnerability not found in map: %s", unresolved.Vulnerability.ID)
			}

			summary.Unresolved = append(summary.Unresolved, *rawVuln)
		}
	}

	return nil
}

func setPins(summary *definitions.Remediation, remSummary remediation.Summary) {
	for _, pin := range remSummary.Pins {
		from := legacyUtils.JoinNameAndVersion(pin.From.Name, pin.From.Version)
		to := legacyUtils.JoinNameAndVersion(pin.To.Name, pin.To.Version)

		vulns := make([]string, 0, len(pin.Fixes))
		for _, fixes := range pin.Fixes {
			vulns = append(vulns, string(fixes.Vulnerability.ID))
		}

		summary.Pin[from] = definitions.PinRemediation{
			IsTransitive: true, // By definition, pins will always be transitive
			UpgradeTo:    to,
			Vulns:        vulns,
		}
	}
}

func setUpgrades(summary *definitions.Remediation, remSummary remediation.Summary) {
	for _, upgrade := range remSummary.Upgrades {
		from := legacyUtils.JoinNameAndVersion(upgrade.From.Name, upgrade.From.Version)
		to := legacyUtils.JoinNameAndVersion(upgrade.To.Name, upgrade.To.Version)

		type vulnUpgradePair struct {
			vuln    string
			upgrade string
		}
		pairs := make([]vulnUpgradePair, 0, len(upgrade.Fixes))
		for _, fixes := range upgrade.Fixes {
			pairs = append(pairs, vulnUpgradePair{
				vuln:    string(fixes.Vulnerability.ID),
				upgrade: legacyUtils.JoinNameAndVersion(fixes.VulnerablePackage.Name, fixes.VulnerablePackage.Version),
			})
		}

		slices.SortFunc(pairs, func(a, b vulnUpgradePair) int {
			if a.vuln < b.vuln {
				return -1
			}
			if a.vuln > b.vuln {
				return 1
			}
			return 0
		})

		upgrades := make([]string, len(pairs))
		vulns := make([]string, len(pairs))
		for i, pair := range pairs {
			vulns[i] = pair.vuln
			upgrades[i] = pair.upgrade
		}

		summary.Upgrade[from] = definitions.RemediationUpgradeInfo{
			UpgradeTo: to,
			Upgrades:  upgrades,
			Vulns:     vulns,
		}
	}
}

// RemediationSummaryToLegacy will convert a remediation.Summary into the legacy `--json` remediation field.
func RemediationSummaryToLegacy(legacyVulns []definitions.Vulnerability, remSummary remediation.Summary) (*definitions.Remediation, error) {
	if len(remSummary.Unresolved) == 0 && len(remSummary.Pins) == 0 && len(remSummary.Upgrades) == 0 {
		//nolint:nilnil // nil is a valid value and will be returned if no remediation information is provided.
		return nil, nil
	}
	summary := definitions.Remediation{
		Pin:        make(map[string]definitions.PinRemediation),
		Upgrade:    make(map[string]definitions.RemediationUpgradeInfo),
		Unresolved: make([]definitions.Vulnerability, 0, len(remSummary.Unresolved)),
	}

	err := setUnresolved(&summary, remSummary, legacyVulns)
	if err != nil {
		return nil, err
	}
	setPins(&summary, remSummary)
	setUpgrades(&summary, remSummary)

	return &summary, nil
}

func getVulnKeyByPath(vulnID string, path []string) string {
	return fmt.Sprintf("%s:%s", vulnID, strings.Join(path, ","))
}
