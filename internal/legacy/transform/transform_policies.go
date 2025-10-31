package transform

import (
	"fmt"
	"time"

	"github.com/snyk/go-application-framework/pkg/utils"

	testapiinline "github.com/snyk/cli-extension-os-flows/internal/util/testapi"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"

	"github.com/snyk/cli-extension-os-flows/internal/legacy/definitions"
)

// ProcessPolicyRelationshipsForVuln mutates the vuln by setting fields derived from the policy relationships of a finding.
func ProcessPolicyRelationshipsForVuln(vuln *definitions.Vulnerability, policyRelationship *testapiinline.PolicyRelationship, logger *zerolog.Logger) {
	if policyRelationship == nil {
		return
	}

	policies := policyRelationship.Data.Attributes.Policies
	if len(policies) == 0 {
		return
	}

	policy, err := deserialisePolicy(policies[0])
	if err != nil {
		logger.Error().Err(err).Msg("error reading the applied policy")
		return
	}

	if policy.Ignore != nil {
		processIgnorePolicyForVuln(vuln, *policy.Ignore)
	}

	if policy.SeverityChange != nil {
		processSeverityChangePolicyForVuln(vuln, *policy.SeverityChange)
	}
}

func processIgnorePolicyForVuln(vuln *definitions.Vulnerability, ignore testapi.Ignore) {
	vuln.IsIgnored = utils.Ptr(true)
	legacyIgnore := buildLegacyIgnore(&ignore.Ignore)
	vuln.Filtered = buildFiltered(legacyIgnore)
	if ignore.Rule != nil {
		vuln.AppliedPolicyRules = buildAppliedPolicyRules(ignore, legacyIgnore)
	}
	vuln.SecurityPolicyMetaData = buildSecurityPolicyMetaData(legacyIgnore)
}

func processSeverityChangePolicyForVuln(vuln *definitions.Vulnerability, severityChange testapi.SeverityChange) {
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
	vuln.AppliedPolicyRules = &definitions.AppliedPolicyRules{
		SeverityChange:   &change,
		SeverityOverride: &change,
	}
}

func deserialisePolicy(policy testapi.Policy) (AppliedPolicy, error) {
	discriminator, err := policy.AppliedPolicy.Discriminator()
	if err != nil {
		return AppliedPolicy{}, err
	}

	switch discriminator {
	case "severity-change":
		severityChange, err := policy.AppliedPolicy.AsSeverityChange()
		if err != nil {
			return AppliedPolicy{}, err
		}
		return AppliedPolicy{SeverityChange: &severityChange}, nil
	case "ignore":
		ignore, err := policy.AppliedPolicy.AsIgnore()
		if err != nil {
			return AppliedPolicy{}, err
		}
		return AppliedPolicy{Ignore: &ignore}, nil
	}

	return AppliedPolicy{}, fmt.Errorf("unexpected policy %s", discriminator)

}

type AppliedPolicy struct {
	Ignore         *testapi.Ignore
	SeverityChange *testapi.SeverityChange
}

func buildLegacyIgnore(ignore *testapi.IgnoreDetails) definitions.VulnFilteredIgnored {
	path := ignorePath(ignore)

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
		DisregardIfFixable: deref(ignore.DisregardIfFixable, false),
		ReasonType:         string(deref(ignore.ReasonType, "")),
		IgnoredBy:          ignoredBy,
		Path:               path,
		Reason:             ignore.Reason,
		Source:             ignore.Source,
	}
}

func buildFiltered(legacyIgnore definitions.VulnFilteredIgnored) *definitions.VulnFiltered {
	return &definitions.VulnFiltered{
		Ignored: &[]definitions.VulnFilteredIgnored{legacyIgnore},
	}
}

func buildAppliedPolicyRules(ignore testapi.Ignore, legacyIgnore definitions.VulnFilteredIgnored) *definitions.AppliedPolicyRules {
	return &definitions.AppliedPolicyRules{
		Ignore: &definitions.AppliedPolicyRulesIgnore{
			Id:     ignore.Rule.Id.String(),
			Type:   string(ignore.ActionType),
			Ignore: legacyIgnore,
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

func buildSecurityPolicyMetaData(legacyIgnore definitions.VulnFilteredIgnored) *definitions.SecurityPolicyMetaData {
	return &definitions.SecurityPolicyMetaData{
		Ignore: legacyIgnore,
	}
}

func reasonTypeToString(reasonType *testapi.IgnoreDetailsReasonType) string {
	if reasonType == nil {
		return ""
	}
	return string(*reasonType)
}

func ignorePath(ignore *testapi.IgnoreDetails) []map[string]string {
	path := []map[string]string{}
	if ignore.Path != nil {
		for _, module := range *ignore.Path {
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

func deref[T any](ptr *T, defaultValue T) T {
	if ptr == nil {
		return defaultValue
	}
	return *ptr
}
