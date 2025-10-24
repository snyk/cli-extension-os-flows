package transform

import "github.com/snyk/cli-extension-os-flows/internal/legacy/definitions"

type VulnerabilityReport struct {
	Vulnerabilities []definitions.Vulnerability
	Ignored         []definitions.Vulnerability
}

func SeparateIgnoredVulnerabilities(vulnerabilities []definitions.Vulnerability, ignorePolicies bool) VulnerabilityReport {
	if ignorePolicies {
		return VulnerabilityReport{
			Vulnerabilities: vulnerabilities,
			Ignored:         nil,
		}
	}

	vulns := []definitions.Vulnerability{}
	ignored := []definitions.Vulnerability{}

	for _, vuln := range vulnerabilities {
		if vuln.IsIgnored != nil && *vuln.IsIgnored {
			ignored = append(ignored, vuln)
		} else {
			vulns = append(vulns, vuln)
		}
	}

	return VulnerabilityReport{
		Vulnerabilities: vulns,
		Ignored:         ignored,
	}
}
