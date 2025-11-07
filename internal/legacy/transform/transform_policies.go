package transform

import (
	"fmt"
	"time"

	"github.com/snyk/go-application-framework/pkg/utils"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"

	"github.com/snyk/cli-extension-os-flows/internal/legacy/definitions"
)

// ProcessPoliciesAndSuppressionsForVuln mutates the vuln by setting fields derived from the policy relationships of a finding.
func ProcessPoliciesAndSuppressionsForVuln(vuln *definitions.Vulnerability, finding *testapi.FindingData, logger *zerolog.Logger) {
	ignorePolicy, err := ignorePolicyOrNil(finding)
	if err != nil {
		logger.Error().Err(err).Msg("error reading the applied policy")
		return
	}

	severityChangePolicy, err := severityChangePolicyOrNil(finding)
	if err != nil {
		logger.Error().Err(err).Msg("error reading severity change policy")
		return
	}

	suppression := finding.Attributes.Suppression
	if suppression != nil {
		processSuppressionForVuln(vuln, *suppression, ignorePolicy)
	}

	if severityChangePolicy != nil {
		processSeverityChangeForVuln(vuln, severityChangePolicy)
	}
}

func processSuppressionForVuln(vuln *definitions.Vulnerability, suppression testapi.Suppression, ignore *testapi.Ignore) {
	vuln.IsIgnored = utils.Ptr(true)

	if ignore != nil {
		legacyIgnore := buildLegacyIgnore(&ignore.Ignore)
		vuln.Filtered = buildFiltered(&legacyIgnore)
		if ignore.Rule != nil {
			vuln.AppliedPolicyRules = buildAppliedPolicyRules(ignore, &legacyIgnore)
		}
		vuln.SecurityPolicyMetaData = buildSecurityPolicyMetaData(&legacyIgnore)
	} else {
		vuln.Filtered = buildFiltered(&definitions.VulnFilteredIgnored{
			Created: formatTime(suppression.CreatedAt, time.RFC3339Nano),
			Expires: formatTime(suppression.ExpiresAt, time.RFC3339Nano),
			Reason:  *suppression.Justification,
			Path:    buildArrayPath(suppression.Path),
			Source:  "cli",
		})
	}
}

func buildArrayPath(path *[]string) []interface{} {
	if path == nil {
		return nil
	}
	pathInterface := make([]interface{}, 0, len(*path))
	for _, p := range *path {
		pathInterface = append(pathInterface, p)
	}
	return pathInterface
}

func processSeverityChangeForVuln(vuln *definitions.Vulnerability, severityChange *testapi.SeverityChange) {
	vuln.OriginalSeverity = (*definitions.VulnerabilitySeverity)(&severityChange.SeverityChange.OriginalSeverity)
	change := definitions.AppliedPolicyRulesSeverityChange{
		Id:   severityChange.Rule.Id.String(),
		Type: "severity-override",
		Rule: definitions.SeverityChangePolicyRule{
			Id:   severityChange.Rule.Id.String(),
			Type: "policy_rule",
			Attributes: definitions.SeverityChangePolicyRuleAttributes{
				Name:     severityChange.Rule.Name,
				Modified: severityChange.Rule.Modified.Format(time.RFC3339Nano),
				Created:  severityChange.Rule.Created.Format(time.RFC3339Nano),
				Review:   string(severityChange.Rule.Review),
				Actions: []definitions.SeverityChangePolicyRuleAction{
					{
						Type: "severity-override",
						Data: definitions.SeverityChangePolicyRuleActionData{
							Severity: string(severityChange.SeverityChange.NewSeverity),
						},
					},
				},
			},
		},
		Policy: definitions.Policy{
			Id:    severityChange.PolicyRef.Id.String(),
			Owner: "group",
		},
		OriginalSeverity: string(severityChange.SeverityChange.OriginalSeverity),
		Severity:         string(severityChange.SeverityChange.NewSeverity),
		NewSeverity:      string(severityChange.SeverityChange.NewSeverity),
	}
	if vuln.AppliedPolicyRules == nil {
		vuln.AppliedPolicyRules = &definitions.AppliedPolicyRules{}
	}
	vuln.AppliedPolicyRules.SeverityChange = &change
	vuln.AppliedPolicyRules.SeverityOverride = &change
}

func policiesOrNil(finding *testapi.FindingData) []testapi.Policy {
	if finding.Relationships == nil {
		return nil
	}

	if finding.Relationships.Policy == nil {
		return nil
	}

	if finding.Relationships.Policy.Data == nil {
		return nil
	}

	if finding.Relationships.Policy.Data.Attributes == nil {
		return nil
	}

	if finding.Relationships.Policy.Data.Attributes.Policies == nil {
		return nil
	}

	return finding.Relationships.Policy.Data.Attributes.Policies
}

func ignorePolicyOrNil(finding *testapi.FindingData) (*testapi.Ignore, error) {
	policies := policiesOrNil(finding)

	for _, policy := range policies {
		discriminator, err := policy.AppliedPolicy.Discriminator()
		if err != nil {
			return nil, fmt.Errorf("failed to determine discriminator for policy %s: %w", policy.Id, err)
		}
		if discriminator == "ignore" {
			ignore, err := policy.AppliedPolicy.AsIgnore()
			if err != nil {
				return nil, fmt.Errorf("failed to convert ignore policy: %w", err)
			}
			return &ignore, nil
		}
	}

	return nil, nil //nolint:nilnil // returning nil pointer with nil error is intentional when no policy is found
}

func severityChangePolicyOrNil(finding *testapi.FindingData) (*testapi.SeverityChange, error) {
	policies := policiesOrNil(finding)

	for _, policy := range policies {
		discriminator, err := policy.AppliedPolicy.Discriminator()
		if err != nil {
			return nil, fmt.Errorf("failed to determine discriminator for policy %s: %w", policy.Id, err)
		}
		if discriminator == "severity-change" {
			severityChange, err := policy.AppliedPolicy.AsSeverityChange()
			if err != nil {
				return nil, fmt.Errorf("failed to convert severity change policy: %w", err)
			}
			return &severityChange, nil
		}
	}

	return nil, nil //nolint:nilnil // returning nil pointer with nil error is intentional when no policy is found
}

func buildLegacyIgnore(ignore *testapi.IgnoreDetails) definitions.VulnFilteredIgnored {
	ignoredBy := definitions.VulnFilteredIgnoredBy{
		IsGroupPolicy: ignore.IgnoredBy.Email == nil,
	}
	if ignore.IgnoredBy != nil {
		ignoredBy.Id = ignore.IgnoredBy.Id.String()
		ignoredBy.Name = ignore.IgnoredBy.Name
		ignoredBy.Email = ignore.IgnoredBy.Email
	}

	return definitions.VulnFilteredIgnored{
		Created:            formatTime(ignore.Created, time.RFC3339Nano),
		Expires:            formatTime(ignore.Expires, time.RFC3339),
		DisregardIfFixable: ignore.DisregardIfFixable,
		ReasonType:         (*string)(ignore.ReasonType),
		IgnoredBy:          &ignoredBy,
		Path:               ignorePath(ignore.Path),
		Reason:             ignore.Reason,
		Source:             ignore.Source,
	}
}

func buildFiltered(legacyIgnore *definitions.VulnFilteredIgnored) *definitions.VulnFiltered {
	return &definitions.VulnFiltered{
		Ignored: &[]definitions.VulnFilteredIgnored{*legacyIgnore},
	}
}

func buildAppliedPolicyRules(ignore *testapi.Ignore, legacyIgnore *definitions.VulnFilteredIgnored) *definitions.AppliedPolicyRules {
	return &definitions.AppliedPolicyRules{
		Ignore: &definitions.AppliedPolicyRulesIgnore{
			Id:     ignore.Rule.Id.String(),
			Type:   string(ignore.ActionType),
			Ignore: *legacyIgnore,
			Rule: definitions.IgnorePolicyRule{
				Id:   ignore.Rule.Id.String(),
				Type: "policy_rule",
				Attributes: definitions.IgnorePolicyRuleAttributes{
					Modified: ignore.Rule.Modified.Format(time.RFC3339Nano),
					Created:  ignore.Rule.Created.Format(time.RFC3339Nano),
					Name:     ignore.Rule.Name,
					Review:   string(ignore.Rule.Review),
					Actions: []definitions.IgnorePolicyRuleAction{
						{
							Type: "ignore",
							Data: definitions.IgnorePolicyRuleActionData{
								IgnoreType: reasonTypeToString(ignore.Ignore.ReasonType),
								Reason:     ignore.Ignore.Reason,
								Source:     ignore.Ignore.Source,
							},
						},
					},
				},
			},
			Policy: definitions.Policy{
				Id:    ignore.Ignore.IgnoredBy.Id.String(),
				Owner: "group",
			},
		},
	}
}

func buildSecurityPolicyMetaData(legacyIgnore *definitions.VulnFilteredIgnored) *definitions.SecurityPolicyMetaData {
	return &definitions.SecurityPolicyMetaData{
		Ignore: *legacyIgnore,
	}
}

func reasonTypeToString(reasonType *testapi.IgnoreDetailsReasonType) string {
	if reasonType == nil {
		return ""
	}
	return string(*reasonType)
}

func ignorePath(ignorePath *[]string) []interface{} {
	var path []interface{}
	if ignorePath != nil {
		for _, module := range *ignorePath {
			path = append(path, map[string]string{"module": module})
		}
	}
	return path
}

func formatTime(t *time.Time, layout string) string {
	if t == nil {
		return ""
	}
	return t.Format(layout)
}
