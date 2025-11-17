package transform_test

import (
	"testing"

	"github.com/snyk/cli-extension-os-flows/internal/legacy/transform"

	"github.com/snyk/cli-extension-os-flows/internal/legacy/definitions"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
	require.NotNil(t, ignored.Expires)
	assert.Equal(t, "2025-11-08T00:00:00Z", *ignored.Expires)
	require.Len(t, ignored.Path, 1)
	assert.Equal(t, map[string]string{"module": "*"}, ignored.Path[0])
	assert.Equal(t, "0b515878-ae96-4c25-8389-d63cc552990e", ignored.IgnoredBy.Id)
	assert.Equal(t, "First Last", ignored.IgnoredBy.Name)
	require.NotNil(t, ignored.IgnoredBy.Email)
	assert.Equal(t, "first.last@snyk.io", *ignored.IgnoredBy.Email)
	assert.Equal(t, false, ignored.IgnoredBy.IsGroupPolicy)

	assert.Nil(t, vuln.Ignores)
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
	assert.Nil(t, ignored.Expires)
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

	require.NotNil(t, vuln.Ignores)
	ignores := *vuln.Ignores
	require.Len(t, ignores, 1)
	require.Len(t, ignores[0].Path, 1)
	assert.Equal(t, map[string]string{"module": "*"}, ignores[0].Path[0])
	assert.Equal(t, "vuln ignored by group policy for test reasons", ignores[0].Reason)
	require.NotNil(t, ignores[0].ReasonType)
	assert.Equal(t, "wont-fix", *ignores[0].ReasonType)
	assert.Equal(t, "unknown", ignores[0].Source)
	assert.Equal(t, "2025-10-27T17:31:19.674Z", ignores[0].Created)
	assert.False(t, *ignores[0].DisregardIfFixable)
	assert.Equal(t, "3cc427b2-35dc-4ce7-bd12-b7ea95d01f68", ignores[0].IgnoredBy.Id)
	assert.Equal(t, "Ignored by security policy", ignores[0].IgnoredBy.Name)
	assert.Nil(t, ignores[0].IgnoredBy.Email)
	assert.True(t, ignores[0].IgnoredBy.IsGroupPolicy)
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
	require.NotNil(t, ignored.Expires)
	assert.Equal(t, "2025-12-30T17:31:05.877Z", *ignored.Expires)
	assert.Equal(t, "there is no fix available", ignored.Reason)
	require.Len(t, ignored.Path, 1)
	assert.Equal(t, "*", ignored.Path[0])
	assert.Nil(t, ignored.ReasonType)
	assert.Nil(t, ignored.DisregardIfFixable)
	assert.Nil(t, ignored.IgnoredBy)

	assert.Empty(t, vuln.Ignores)
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
	assert.Equal(t, "2025-11-07T12:11:45.477Z", ignored.Created)
	assert.False(t, *ignored.DisregardIfFixable)

	require.Len(t, ignored.Path, 1)
	assert.Equal(t, map[string]string{"module": "*"}, ignored.Path[0])

	assert.Equal(t, "3cc427b2-35dc-4ce7-bd12-b7ea95d01f68", ignored.IgnoredBy.Id)
	assert.Equal(t, "Ignored by security policy", ignored.IgnoredBy.Name)
	assert.Nil(t, ignored.IgnoredBy.Email)
	assert.True(t, ignored.IgnoredBy.IsGroupPolicy)

	require.NotNil(t, vuln.AppliedPolicyRules)
	ignore := vuln.AppliedPolicyRules.Ignore
	require.NotNil(t, ignore)
	assert.Equal(t, "10cbb99a-97e7-413e-9656-a57e1fe43434", ignore.Id)
	assert.Equal(t, "ignore", ignore.Type)
	require.Len(t, ignore.Ignore.Path, 1)
	assert.Equal(t, map[string]string{"module": "*"}, ignore.Ignore.Path[0])
	assert.Equal(t, "not vulnerable according to the group policy", ignore.Ignore.Reason)
	require.NotNil(t, ignore.Ignore.ReasonType)
	assert.Equal(t, "not-vulnerable", *ignore.Ignore.ReasonType)
	assert.Equal(t, "unknown", ignore.Ignore.Source)
	assert.Equal(t, "2025-11-07T12:11:45.477Z", ignore.Ignore.Created)
	assert.False(t, *ignore.Ignore.DisregardIfFixable)
	assert.Equal(t, "3cc427b2-35dc-4ce7-bd12-b7ea95d01f68", ignore.Ignore.IgnoredBy.Id)
	assert.Equal(t, "Ignored by security policy", ignore.Ignore.IgnoredBy.Name)
	assert.Nil(t, ignore.Ignore.IgnoredBy.Email)
	assert.True(t, ignore.Ignore.IgnoredBy.IsGroupPolicy)

	assert.Equal(t, "10cbb99a-97e7-413e-9656-a57e1fe43434", ignore.Rule.Id)
	assert.Equal(t, "policy_rule", ignore.Rule.Type)
	assert.Equal(t, "2025-11-07T12:11:45.477702Z", ignore.Rule.Attributes.Modified)
	assert.Equal(t, "Rule 1", ignore.Rule.Attributes.Name)
	assert.Equal(t, "not-required", ignore.Rule.Attributes.Review)
	assert.Equal(t, "2025-11-07T12:11:45.477702Z", ignore.Rule.Attributes.Created)
	assert.Len(t, ignore.Rule.Attributes.Actions, 1)
	assert.Equal(t, "ignore", ignore.Rule.Attributes.Actions[0].Type)
	assert.Equal(t, "not-vulnerable", ignore.Rule.Attributes.Actions[0].Data.IgnoreType)
	assert.Equal(t, "not vulnerable according to the group policy", ignore.Rule.Attributes.Actions[0].Data.Reason)
	assert.Equal(t, "group", ignore.Policy.Owner)
	assert.Equal(t, "3cc427b2-35dc-4ce7-bd12-b7ea95d01f68", ignore.Policy.Id)

	assert.NotNil(t, vuln.SecurityPolicyMetaData)
	require.Len(t, vuln.SecurityPolicyMetaData.Ignore.Path, 1)
	assert.Equal(t, map[string]string{"module": "*"}, vuln.SecurityPolicyMetaData.Ignore.Path[0])
	assert.Equal(t, "not vulnerable according to the group policy", vuln.SecurityPolicyMetaData.Ignore.Reason)
	require.NotNil(t, vuln.SecurityPolicyMetaData.Ignore.ReasonType)
	assert.Equal(t, "not-vulnerable", *vuln.SecurityPolicyMetaData.Ignore.ReasonType)
	assert.Equal(t, "unknown", vuln.SecurityPolicyMetaData.Ignore.Source)
	assert.Equal(t, "2025-11-07T12:11:45.477Z", vuln.SecurityPolicyMetaData.Ignore.Created)
	assert.False(t, *vuln.SecurityPolicyMetaData.Ignore.DisregardIfFixable)
	assert.Equal(t, "3cc427b2-35dc-4ce7-bd12-b7ea95d01f68", vuln.SecurityPolicyMetaData.Ignore.IgnoredBy.Id)
	assert.Equal(t, "Ignored by security policy", vuln.SecurityPolicyMetaData.Ignore.IgnoredBy.Name)
	assert.Nil(t, vuln.SecurityPolicyMetaData.Ignore.IgnoredBy.Email)
	assert.True(t, vuln.SecurityPolicyMetaData.Ignore.IgnoredBy.IsGroupPolicy)

	require.NotNil(t, vuln.Ignores)
	require.Len(t, *vuln.Ignores, 1)
}

func TestIgnoredBy_TypeField_InFinalJSON(t *testing.T) {
	tests := []struct {
		name         string
		findingsFile string
		expectedType string
	}{
		{
			name:         "user ignore in JSON",
			findingsFile: "testdata/projectIgnore-findings.json",
			expectedType: "user",
		},
		{
			name:         "group policy ignore in JSON",
			findingsFile: "testdata/policyGroupIgnore-findings.json",
			expectedType: "group",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := loadFindings(t, tt.findingsFile)
			vulns, err := transform.FindingsToLegacyVulns(findings, "package-manager", utils.Ptr(zerolog.Nop()))
			require.NoError(t, err)

			vulnReport := transform.SeparateIgnoredVulnerabilities(vulns, false)

			response := definitions.LegacyVulnerabilityResponse{
				Filtered: definitions.Filtered{
					Ignore: vulnReport.Ignored,
					Patch:  make([]string, 0),
				},
			}

			require.NotEmpty(t, response.Filtered.Ignore)
			firstIgnoredVuln := response.Filtered.Ignore[0]
			require.NotNil(t, firstIgnoredVuln.Filtered)
			require.NotNil(t, firstIgnoredVuln.Filtered.Ignored)
			require.NotEmpty(t, *firstIgnoredVuln.Filtered.Ignored)

			ignored := (*firstIgnoredVuln.Filtered.Ignored)[0]
			require.NotNil(t, ignored.IgnoredBy)
			require.NotNil(t, ignored.IgnoredBy.Type)
			assert.Equal(t, tt.expectedType, *ignored.IgnoredBy.Type)
		})
	}
}
