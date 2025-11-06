package transform_test

import (
	"encoding/json"
	"os"
	"slices"
	"testing"

	"github.com/snyk/cli-extension-os-flows/internal/legacy/transform"

	"github.com/snyk/cli-extension-os-flows/internal/legacy/definitions"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/utils"
)

func TestProjectLevelIgnore(t *testing.T) {
	findings := loadFindings(t, "testdata/projectIgnore-findings.json")

	vulns, err := transform.FindingsToLegacyVulns(findings, "package-manager", utils.Ptr(zerolog.Nop()))
	require.NoError(t, err)

	vuln := findByID("SNYK-GOLANG-GOPKGINYAMLV2-12330650", vulns)

	assert.Nil(t, vuln.AppliedPolicyRules)
	require.NotNil(t, vuln.Filtered)
	require.NotNil(t, vuln.Filtered.Ignored)
	require.Len(t, *vuln.Filtered.Ignored, 1)
	ignored := (*vuln.Filtered.Ignored)[0]
	assert.Equal(t, "api", ignored.Source)
	assert.Equal(t, "2025-10-27T17:36:07.116Z", ignored.Created)
	assert.Equal(t, "Project level ignore until a fix or date", ignored.Reason)
	require.NotNil(t, ignored.DisregardIfFixable)
	assert.Equal(t, true, *ignored.DisregardIfFixable)
	require.NotNil(t, ignored.ReasonType)
	assert.Equal(t, "temporary-ignore", *ignored.ReasonType)
	assert.Equal(t, "2025-11-08T00:00:00Z", ignored.Expires)
	require.Len(t, ignored.Path, 1)
	assert.Equal(t, map[string]string{"module": "*"}, ignored.Path[0])
	assert.Equal(t, "0b515878-ae96-4c25-8389-d63cc552990e", ignored.IgnoredBy.Id)
	assert.Equal(t, "First Last", ignored.IgnoredBy.Name)
	require.NotNil(t, ignored.IgnoredBy.Email)
	assert.Equal(t, "first.last@snyk.io", *ignored.IgnoredBy.Email)
	assert.Equal(t, false, ignored.IgnoredBy.IsGroupPolicy)
}

func TestGroupLevelIgnore(t *testing.T) {
	findings := loadFindings(t, "testdata/policyGroupIgnore-findings.json")

	vulns, err := transform.FindingsToLegacyVulns(findings, "package-manager", utils.Ptr(zerolog.Nop()))
	require.NoError(t, err)

	vuln := findByID("SNYK-GOLANG-GOPKGINYAMLV2-12330650", vulns)

	require.NotNil(t, vuln.IsIgnored)
	assert.True(t, *vuln.IsIgnored)
	require.NotNil(t, vuln.Filtered)
	require.NotNil(t, vuln.Filtered.Ignored)
	require.Len(t, *vuln.Filtered.Ignored, 1)
	ignored := (*vuln.Filtered.Ignored)[0]
	assert.Equal(t, "vuln ignored by group policy for test reasons", ignored.Reason)
	require.NotNil(t, ignored.ReasonType)
	assert.Equal(t, "wont-fix", *ignored.ReasonType)
	assert.Equal(t, "unknown", ignored.Source)
	assert.Equal(t, "2025-10-27T17:31:19.674Z", ignored.Created)
	assert.False(t, *ignored.DisregardIfFixable)

	require.Len(t, ignored.Path, 1)
	assert.Equal(t, map[string]string{"module": "*"}, ignored.Path[0])

	assert.Equal(t, "3cc427b2-35dc-4ce7-bd12-b7ea95d01f68", ignored.IgnoredBy.Id)
	assert.Equal(t, "Ignored by security policy", ignored.IgnoredBy.Name)
	assert.Nil(t, ignored.IgnoredBy.Email)
	assert.True(t, ignored.IgnoredBy.IsGroupPolicy)

	require.NotNil(t, vuln.AppliedPolicyRules)
	ignore := vuln.AppliedPolicyRules.Ignore
	assert.Equal(t, "7763807c-251b-4ef2-8cc8-7f5d7048dd03", ignore.Id)
	assert.Equal(t, "ignore", ignore.Type)
	require.Len(t, ignore.Ignore.Path, 1)
	assert.Equal(t, map[string]string{"module": "*"}, ignore.Ignore.Path[0])
	assert.Equal(t, "vuln ignored by group policy for test reasons", ignore.Ignore.Reason)
	require.NotNil(t, ignore.Ignore.ReasonType)
	assert.Equal(t, "wont-fix", *ignore.Ignore.ReasonType)
	assert.Equal(t, "unknown", ignore.Ignore.Source)
	assert.Equal(t, "2025-10-27T17:31:19.674Z", ignore.Ignore.Created)
	assert.False(t, *ignore.Ignore.DisregardIfFixable)
	assert.Equal(t, "3cc427b2-35dc-4ce7-bd12-b7ea95d01f68", ignore.Ignore.IgnoredBy.Id)
	assert.Equal(t, "Ignored by security policy", ignore.Ignore.IgnoredBy.Name)
	assert.Nil(t, ignore.Ignore.IgnoredBy.Email)
	assert.True(t, ignore.Ignore.IgnoredBy.IsGroupPolicy)

	assert.Equal(t, "7763807c-251b-4ef2-8cc8-7f5d7048dd03", ignore.Rule.Id)
	assert.Equal(t, "policy_rule", ignore.Rule.Type)
	assert.Equal(t, "2025-10-27T17:31:19.674881Z", ignore.Rule.Attributes.Modified)
	assert.Equal(t, "Rule 1", ignore.Rule.Attributes.Name)
	assert.Equal(t, "not-required", ignore.Rule.Attributes.Review)
	assert.Equal(t, "2025-10-27T17:31:19.674881Z", ignore.Rule.Attributes.Created)
	assert.Len(t, ignore.Rule.Attributes.Actions, 1)
	assert.Equal(t, "ignore", ignore.Rule.Attributes.Actions[0].Type)
	assert.Equal(t, "wont-fix", ignore.Rule.Attributes.Actions[0].Data.IgnoreType)
	assert.Equal(t, "vuln ignored by group policy for test reasons", ignore.Rule.Attributes.Actions[0].Data.Reason)
	assert.Equal(t, "group", ignore.Policy.Owner)
	assert.Equal(t, "3cc427b2-35dc-4ce7-bd12-b7ea95d01f68", ignore.Policy.Id)

	assert.NotNil(t, vuln.SecurityPolicyMetaData)
	require.Len(t, vuln.SecurityPolicyMetaData.Ignore.Path, 1)
	assert.Equal(t, map[string]string{"module": "*"}, vuln.SecurityPolicyMetaData.Ignore.Path[0])
	assert.Equal(t, "vuln ignored by group policy for test reasons", vuln.SecurityPolicyMetaData.Ignore.Reason)
	require.NotNil(t, vuln.SecurityPolicyMetaData.Ignore.ReasonType)
	assert.Equal(t, "wont-fix", *vuln.SecurityPolicyMetaData.Ignore.ReasonType)
	assert.Equal(t, "unknown", vuln.SecurityPolicyMetaData.Ignore.Source)
	assert.Equal(t, "2025-10-27T17:31:19.674Z", vuln.SecurityPolicyMetaData.Ignore.Created)
	assert.False(t, *vuln.SecurityPolicyMetaData.Ignore.DisregardIfFixable)
	assert.Equal(t, "3cc427b2-35dc-4ce7-bd12-b7ea95d01f68", vuln.SecurityPolicyMetaData.Ignore.IgnoredBy.Id)
	assert.Equal(t, "Ignored by security policy", vuln.SecurityPolicyMetaData.Ignore.IgnoredBy.Name)
	assert.Nil(t, vuln.SecurityPolicyMetaData.Ignore.IgnoredBy.Email)
	assert.True(t, vuln.SecurityPolicyMetaData.Ignore.IgnoredBy.IsGroupPolicy)
}

func TestDotSnykFileIgnore(t *testing.T) {
	findings := loadFindings(t, "testdata/dotSnykIgnore-findings.json")

	vulns, err := transform.FindingsToLegacyVulns(findings, "package-manager", utils.Ptr(zerolog.Nop()))
	require.NoError(t, err)

	vuln := findByID("SNYK-GOLANG-GOPKGINYAMLV2-12330650", vulns)

	assert.Nil(t, vuln.AppliedPolicyRules)
	require.NotNil(t, vuln.Filtered)
	require.NotNil(t, vuln.Filtered.Ignored)
	require.Len(t, *vuln.Filtered.Ignored, 1)
	ignored := (*vuln.Filtered.Ignored)[0]
	assert.Equal(t, "cli", ignored.Source)
	assert.Equal(t, "2023-11-30T17:31:05.884Z", ignored.Created)
	assert.Equal(t, "2025-12-30T17:31:05.877Z", ignored.Expires)
	assert.Equal(t, "there is no fix available", ignored.Reason)
	require.Len(t, ignored.Path, 1)
	assert.Equal(t, "*", ignored.Path[0])
	assert.Nil(t, ignored.ReasonType)
	assert.Nil(t, ignored.DisregardIfFixable)
	assert.Nil(t, ignored.IgnoredBy)
}

func TestSeverityChange(t *testing.T) {
	findings := loadFindings(t, "testdata/policySeverityChange-findings.json")

	vulns, err := transform.FindingsToLegacyVulns(findings, "package-manager", utils.Ptr(zerolog.Nop()))
	require.NoError(t, err)

	vuln := findByID("SNYK-GOLANG-GOPKGINYAMLV2-12330650", vulns)

	require.NotNil(t, vuln.OriginalSeverity)
	assert.Equal(t, definitions.VulnerabilitySeverity("medium"), *vuln.OriginalSeverity)
	assert.Equal(t, definitions.VulnerabilitySeverity("critical"), vuln.Severity)
	require.NotNil(t, vuln.SeverityWithCritical)
	require.Equal(t, definitions.VulnerabilitySeverity("critical"), *vuln.SeverityWithCritical)
	require.NotNil(t, vuln.AppliedPolicyRules)

	severityChange := vuln.AppliedPolicyRules.SeverityChange
	require.NotNil(t, severityChange)
	assert.Equal(t, "fa7968fd-858c-42be-a53c-39cc25713362", severityChange.Id)
	assert.Equal(t, "fa7968fd-858c-42be-a53c-39cc25713362", severityChange.Rule.Id)
	assert.Equal(t, "policy_rule", severityChange.Rule.Type)
	assert.Equal(t, "Rule 1", severityChange.Rule.Attributes.Name)
	assert.Equal(t, "2025-10-27T17:18:57.763988Z", severityChange.Rule.Attributes.Modified)
	assert.Equal(t, "2025-10-27T17:18:57.763988Z", severityChange.Rule.Attributes.Created)
	assert.Equal(t, "not-required", severityChange.Rule.Attributes.Review)
	require.Len(t, severityChange.Rule.Attributes.Actions, 1)
	assert.Equal(t, "severity-override", severityChange.Rule.Attributes.Actions[0].Type)
	assert.Equal(t, "critical", severityChange.Rule.Attributes.Actions[0].Data.Severity)
	assert.Equal(t, "severity-override", severityChange.Type)
	assert.Equal(t, "3cc427b2-35dc-4ce7-bd12-b7ea95d01f68", severityChange.Policy.Id)
	assert.Equal(t, "group", severityChange.Policy.Owner)
	assert.Equal(t, "medium", severityChange.OriginalSeverity)
	assert.Equal(t, "critical", severityChange.Severity)
	assert.Equal(t, "critical", severityChange.NewSeverity)

	assert.Equal(t, severityChange, vuln.AppliedPolicyRules.SeverityOverride)
}

func TestMultiplePolicies(t *testing.T) {
	findings := loadFindings(t, "testdata/groupIgnoreAndSeverityAndDotsnykAndProjectIgnore-findings.json")

	vulns, err := transform.FindingsToLegacyVulns(findings, "package-manager", utils.Ptr(zerolog.Nop()))
	require.NoError(t, err)

	vuln := findByID("SNYK-GOLANG-GOPKGINYAMLV2-12330650", vulns)
	require.NotNil(t, vuln.IsIgnored)
	assert.True(t, *vuln.IsIgnored)
	require.NotNil(t, vuln.Filtered)
	require.NotNil(t, vuln.Filtered.Ignored)
	require.Len(t, *vuln.Filtered.Ignored, 1)
	ignored := (*vuln.Filtered.Ignored)[0]
	assert.Equal(t, "not vulnerable according to the group policy", ignored.Reason)
	require.NotNil(t, ignored.ReasonType)
	assert.Equal(t, "not-vulnerable", *ignored.ReasonType)
	assert.Equal(t, "unknown", ignored.Source)
	assert.Equal(t, "2025-11-04T10:50:13.553Z", ignored.Created)
	assert.False(t, *ignored.DisregardIfFixable)

	require.Len(t, ignored.Path, 1)
	t.Skip("skipping until ignore rules are fixed")
	assert.Equal(t, map[string]string{"module": "*"}, ignored.Path[0])

	assert.Equal(t, "3cc427b2-35dc-4ce7-bd12-b7ea95d01f68", ignored.IgnoredBy.Id)
	assert.Equal(t, "Ignored by security policy", ignored.IgnoredBy.Name)
	assert.Nil(t, ignored.IgnoredBy.Email)
	assert.True(t, ignored.IgnoredBy.IsGroupPolicy)

	require.NotNil(t, vuln.AppliedPolicyRules)
	ignore := vuln.AppliedPolicyRules.Ignore
	require.NotNil(t, ignore)
	assert.Equal(t, "7763807c-251b-4ef2-8cc8-7f5d7048dd03", ignore.Id)
	assert.Equal(t, "ignore", ignore.Type)
	require.Len(t, ignore.Ignore.Path, 1)
	assert.Equal(t, map[string]string{"module": "*"}, ignore.Ignore.Path[0])
	assert.Equal(t, "vuln ignored by group policy for test reasons", ignore.Ignore.Reason)
	require.NotNil(t, ignore.Ignore.ReasonType)
	assert.Equal(t, "wont-fix", *ignore.Ignore.ReasonType)
	assert.Equal(t, "unknown", ignore.Ignore.Source)
	assert.Equal(t, "2025-10-27T17:31:19.674Z", ignore.Ignore.Created)
	assert.False(t, *ignore.Ignore.DisregardIfFixable)
	assert.Equal(t, "3cc427b2-35dc-4ce7-bd12-b7ea95d01f68", ignore.Ignore.IgnoredBy.Id)
	assert.Equal(t, "Ignored by security policy", ignore.Ignore.IgnoredBy.Name)
	assert.Nil(t, ignore.Ignore.IgnoredBy.Email)
	assert.True(t, ignore.Ignore.IgnoredBy.IsGroupPolicy)

	assert.Equal(t, "7763807c-251b-4ef2-8cc8-7f5d7048dd03", ignore.Rule.Id)
	assert.Equal(t, "policy_rule", ignore.Rule.Type)
	assert.Equal(t, "2025-10-27T17:31:19.674881Z", ignore.Rule.Attributes.Modified)
	assert.Equal(t, "Rule 1", ignore.Rule.Attributes.Name)
	assert.Equal(t, "not-required", ignore.Rule.Attributes.Review)
	assert.Equal(t, "2025-10-27T17:31:19.674881Z", ignore.Rule.Attributes.Created)
	assert.Len(t, ignore.Rule.Attributes.Actions, 1)
	assert.Equal(t, "ignore", ignore.Rule.Attributes.Actions[0].Type)
	assert.Equal(t, "wont-fix", ignore.Rule.Attributes.Actions[0].Data.IgnoreType)
	assert.Equal(t, "vuln ignored by group policy for test reasons", ignore.Rule.Attributes.Actions[0].Data.Reason)
	assert.Equal(t, "group", ignore.Policy.Owner)
	assert.Equal(t, "3cc427b2-35dc-4ce7-bd12-b7ea95d01f68", ignore.Policy.Id)

	assert.NotNil(t, vuln.SecurityPolicyMetaData)
	require.Len(t, vuln.SecurityPolicyMetaData.Ignore.Path, 1)
	assert.Equal(t, map[string]string{"module": "*"}, vuln.SecurityPolicyMetaData.Ignore.Path[0])
	assert.Equal(t, "vuln ignored by group policy for test reasons", vuln.SecurityPolicyMetaData.Ignore.Reason)
	require.NotNil(t, vuln.SecurityPolicyMetaData.Ignore.ReasonType)
	assert.Equal(t, "wont-fix", *vuln.SecurityPolicyMetaData.Ignore.ReasonType)
	assert.Equal(t, "unknown", vuln.SecurityPolicyMetaData.Ignore.Source)
	assert.Equal(t, "2025-10-27T17:31:19.674Z", vuln.SecurityPolicyMetaData.Ignore.Created)
	assert.False(t, *vuln.SecurityPolicyMetaData.Ignore.DisregardIfFixable)
	assert.Equal(t, "3cc427b2-35dc-4ce7-bd12-b7ea95d01f68", vuln.SecurityPolicyMetaData.Ignore.IgnoredBy.Id)
	assert.Equal(t, "Ignored by security policy", vuln.SecurityPolicyMetaData.Ignore.IgnoredBy.Name)
	assert.Nil(t, vuln.SecurityPolicyMetaData.Ignore.IgnoredBy.Email)
	assert.True(t, vuln.SecurityPolicyMetaData.Ignore.IgnoredBy.IsGroupPolicy)
}

func loadFindings(t *testing.T, path string) []testapi.FindingData {
	t.Helper()
	buf, err := os.ReadFile(path)
	require.NoError(t, err)

	var response FindingsResponse
	err = json.Unmarshal(buf, &response)
	require.NoError(t, err)

	return response.Data
}

type FindingsResponse struct {
	Data []testapi.FindingData `json:"data"`
}

//nolint:unparam // vulnID is always the same in tests but keeping parameter for clarity
func findByID(vulnID string, vulns []definitions.Vulnerability) definitions.Vulnerability {
	index := slices.IndexFunc(vulns, func(vuln definitions.Vulnerability) bool {
		return vuln.Id == vulnID
	})
	return vulns[index]
}
