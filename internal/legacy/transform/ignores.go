package transform

import "github.com/snyk/cli-extension-os-flows/internal/legacy/definitions"

// SeparatedVulnerabilities represents the results of splitting vulns into two slices:
// one for ignored vulns and one for non-ignored vulns.
type SeparatedVulnerabilities struct {
	Vulnerabilities []definitions.Vulnerability
	Ignored         []definitions.Vulnerability
}

// SeparateIgnoredVulnerabilities splits all vulnerabilities into ignored and non-ignored.
func SeparateIgnoredVulnerabilities(vulnerabilities []definitions.Vulnerability, ignorePolicies bool) SeparatedVulnerabilities {
	if ignorePolicies {
		return SeparatedVulnerabilities{
			Vulnerabilities: vulnerabilities,
			Ignored:         nil,
		}
	}

	vulns := []definitions.Vulnerability{}
	ignored := []definitions.Vulnerability{}

	for i := range vulnerabilities {
		vuln := vulnerabilities[i]
		if vuln.IsIgnored != nil && *vuln.IsIgnored {
			ignored = append(ignored, vuln)
		} else {
			vulns = append(vulns, vuln)
		}
	}

	return SeparatedVulnerabilities{
		Vulnerabilities: vulns,
		Ignored:         ignored,
	}
}
