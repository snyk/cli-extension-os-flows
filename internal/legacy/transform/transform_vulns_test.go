package transform_test

import (
	"encoding/json"
	"testing"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/legacy/definitions"
	"github.com/snyk/cli-extension-os-flows/internal/legacy/transform"
)

var minimumFinding = testapi.FindingData{
	Attributes: &testapi.FindingAttributes{
		Rating: testapi.Rating{
			Severity: "medium",
		},
	},
}

func TestUpgradePath_WhenNotAvailable_EmptyArray(t *testing.T) {
	vuln, vulnJSON := transformFinding(t, minimumFinding)

	assert.Len(t, vuln.UpgradePath, 0)
	assert.Contains(t, vulnJSON, `"upgradePath":[]`)
}

func TestEPSSDetails_WhenNotAvailable_NotIncludedInJSON(t *testing.T) {
	vuln, vulnJSON := transformFinding(t, minimumFinding)

	assert.Nil(t, vuln.EpssDetails)
	assert.NotContains(t, vulnJSON, `"epssDetails"`)
}

func transformFinding(t *testing.T, finding testapi.FindingData) (vuln definitions.Vulnerability, vulnJSON string) {
	t.Helper()

	vulns, err := transform.FindingsToLegacyVulns([]testapi.FindingData{finding}, "package-manager", utils.Ptr(zerolog.Nop()))
	require.NoError(t, err)
	require.Len(t, vulns, 1)
	vuln = vulns[0]

	vulnBytes, err := json.Marshal(vuln)
	assert.NoError(t, err)

	return vuln, string(vulnBytes)
}

func TestMaturityLevels(t *testing.T) {
	findings := loadFindings(t, "testdata/projectIgnore-findings.json")

	vulns, err := transform.FindingsToLegacyVulns(findings, "package-manager", utils.Ptr(zerolog.Nop()))
	require.NoError(t, err)

	vuln := findByID("SNYK-GOLANG-GOPKGINYAMLV2-12330650", vulns)

	require.NotNil(t, vuln.ExploitDetails)
	require.NotEmpty(t, vuln.ExploitDetails.MaturityLevels)
	require.Equal(t, vuln.ExploitDetails.MaturityLevels[0].Level, "Not Defined")
}

func TestVulnExploit(t *testing.T) {
	findings := loadFindings(t, "testdata/groupIgnoreAndSeverityAndDotsnykAndProjectIgnore-findings.json")

	vulns, err := transform.FindingsToLegacyVulns(findings, "package-manager", utils.Ptr(zerolog.Nop()))
	require.NoError(t, err)

	vuln := findByID("SNYK-GOLANG-GOPKGINYAMLV2-12330650", vulns)

	require.NotNil(t, vuln.Exploit)
	require.Equal(t, "Not Defined", *vuln.Exploit)
}
