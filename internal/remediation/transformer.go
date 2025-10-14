package remediation

import (
	"fmt"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
)

// ShimFindingsToRemediationFindings will convert testapi findings to remediation findings.
func ShimFindingsToRemediationFindings(shimFindings []testapi.FindingData) (Findings, error) {
	var findings Findings
	for _, sf := range shimFindings {
		vuln, err := getFindingVulnProblem(sf)
		if err != nil {
			return nil, fmt.Errorf("failed to get finding vuln: %w", err)
		}
		// We skip over findings without snyk vulns (e.g findings with license issues)
		if vuln == nil {
			continue
		}

		pkg, err := packageFromFinding(sf)
		if err != nil {
			return nil, fmt.Errorf("failed to get finding package: %w", err)
		}

		ecosystem, err := vuln.Ecosystem.AsSnykvulndbBuildPackageEcosystem()
		if err != nil {
			return nil, fmt.Errorf("error converting vuln ecosystem to build package ecosystem: %w", err)
		}

		depPaths, err := depedencyPathsFromFinding(sf)
		if err != nil {
			// return nil, fmt.Errorf("failed to get finding dependency path: %w", err)
			continue
		}

		fix, err := fixFromFinding(sf)
		if err != nil {
			return nil, fmt.Errorf("failed to get finding fix: %w", err)
		}

		findings = append(findings, &Finding{
			Package: pkg,
			Vulnerability: Vulnerability{
				ID:       VulnID(vuln.Id),
				Name:     sf.Attributes.Title,
				Severity: Severity(sf.Attributes.Rating.Severity),
			},
			DependencyPaths: depPaths,
			FixedInVersions: vuln.InitiallyFixedInVersions,
			Fix:             fix,
			PackageManager:  PackageManager(ecosystem.PackageManager),
		})
	}
	return findings, nil
}

func getFindingVulnProblem(sf testapi.FindingData) (*testapi.SnykVulnProblem, error) {
	for _, prob := range sf.Attributes.Problems {
		disc, err := prob.Discriminator()
		if err != nil {
			return nil, fmt.Errorf("error getting problem discriminator: %w", err)
		}
		if disc == string(testapi.SnykVuln) {
			vulnProb, err := prob.AsSnykVulnProblem()
			if err != nil {
				return nil, fmt.Errorf("error converting problem to snyk vuln: %w", err)
			}
			return &vulnProb, nil
		}
	}

	//nolint:nilnil // nil is a valid value and will be returned if no snyk vuln problem is found in the finding.
	return nil, nil
}

func packageFromFinding(sf testapi.FindingData) (Package, error) {
	for _, loc := range sf.Attributes.Locations {
		disc, err := loc.Discriminator()
		if err != nil {
			return Package{}, fmt.Errorf("error getting location discriminator: %w", err)
		}
		if disc == string(testapi.PackageLocationTypePackage) {
			pLoc, err := loc.AsPackageLocation()
			if err != nil {
				return Package{}, fmt.Errorf("error converting location to package location: %w", err)
			}
			return Package{
				Name:    pLoc.Package.Name,
				Version: pLoc.Package.Version,
			}, nil
		}
	}
	return Package{}, fmt.Errorf("finding is missing package location: %s", sf.Id)
}

func depedencyPathsFromFinding(sf testapi.FindingData) ([]DependencyPath, error) {
	var depPaths []DependencyPath
	for _, ev := range sf.Attributes.Evidence {
		disc, err := ev.Discriminator()
		if err != nil {
			return nil, fmt.Errorf("error getting evidence discriminator: %w", err)
		}
		if disc == string(testapi.DependencyPath) {
			depEv, err := ev.AsDependencyPathEvidence()
			if err != nil {
				return nil, fmt.Errorf("error converting evidence to dependency path evidence: %w", err)
			}
			depPath := make([]Package, 0, len(depEv.Path))
			for _, path := range depEv.Path {
				depPath = append(depPath, Package{
					Name:    path.Name,
					Version: path.Version,
				})
			}
			depPaths = append(depPaths, depPath)
		}
	}

	if len(depPaths) == 0 {
		return nil, fmt.Errorf("finding is missing depdency path evidence: %s", sf.Id)
	}

	return depPaths, nil
}

func fixFromFinding(sf testapi.FindingData) (Fix, error) {
	if sf.Relationships != nil &&
		sf.Relationships.Fix != nil &&
		sf.Relationships.Fix.Data != nil &&
		sf.Relationships.Fix.Data.Attributes != nil {
		actionOutcome := sf.Relationships.Fix.Data.Attributes.Outcome
		if actionOutcome == testapi.Unresolved {
			return NewUnresolvedFix(), nil
		}

		action := sf.Relationships.Fix.Data.Attributes.Actions
		disc, err := action.Discriminator()
		if err != nil {
			return nil, fmt.Errorf("error getting action discriminator: %w", err)
		}

		switch disc {
		case string(testapi.UpgradePackage):
			uAction, err := action.AsUpgradePackageAction()
			if err != nil {
				return NewUnresolvedFix(), err
			}
			uPaths := make([]DependencyPath, 0, len(uAction.UpgradePaths))
			for _, actionUpgradePath := range uAction.UpgradePaths {
				uPath := make(DependencyPath, 0, len(uAction.UpgradePaths))
				for _, path := range actionUpgradePath.DependencyPath {
					uPath = append(uPath, Package{
						Name:    path.Name,
						Version: path.Version,
					})
				}
				uPaths = append(uPaths, uPath)
			}
			return NewUpgradeFix(Outcome(actionOutcome), UpgradeAction{
				PackageName:  uAction.PackageName,
				UpgradePaths: uPaths,
			}), nil
		case string(testapi.PinPackage):
			pAction, err := action.AsPinPackageAction()
			if err != nil {
				return NewUnresolvedFix(), err
			}
			return NewPinFix(FullyResolved, PinAction{
				Package{
					Name:    pAction.PackageName,
					Version: pAction.PinVersion,
				},
			}), nil
		}
	}
	return NewUnresolvedFix(), nil
}
