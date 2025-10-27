package transform_test

import (
	"testing"

	"github.com/snyk/cli-extension-os-flows/internal/legacy/transform"

	"github.com/snyk/go-application-framework/pkg/utils"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/cli-extension-os-flows/internal/legacy/definitions"
)

func Test_KeepsNotIgnoredVulns(t *testing.T) {
	vulns := []definitions.Vulnerability{
		{
			IsIgnored: nil,
		},
		{
			IsIgnored: utils.Ptr(false),
		},
	}

	report := transform.SeparateIgnoredVulnerabilities(vulns, false)

	assert.Len(t, report.Vulnerabilities, 2)
	assert.Empty(t, report.Ignored)
}

func Test_SeparatedIgnoredVulns(t *testing.T) {
	vulns := []definitions.Vulnerability{
		{
			IsIgnored: utils.Ptr(true),
		},
	}

	report := transform.SeparateIgnoredVulnerabilities(vulns, false)

	assert.Empty(t, report.Vulnerabilities)
	assert.Len(t, report.Ignored, 1)
}

func Test_WhenIgnoringPolicy_KeepsAllVulns(t *testing.T) {
	vulns := []definitions.Vulnerability{
		{
			IsIgnored: utils.Ptr(true),
		},
	}

	report := transform.SeparateIgnoredVulnerabilities(vulns, true)

	assert.Len(t, report.Vulnerabilities, 1)
	assert.Empty(t, report.Ignored)
}
