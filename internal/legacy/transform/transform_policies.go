package transform

import (
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

	policy := policies[0]
	ignore, err := policy.AppliedPolicy.AsIgnore()
	if err != nil {
		logger.Error().Err(err).Msg("Failed to convert policy to ignore")
		return
	}

	ignoredVuln := buildLegacyIgnore(&ignore.Ignore)

	vuln.IsIgnored = utils.Ptr(true)
	vuln.Filtered = &definitions.VulnFiltered{
		Ignored: &[]definitions.VulnFilteredIgnored{ignoredVuln},
	}
}

func buildLegacyIgnore(ignore *testapi.IgnoreDetails) definitions.VulnFilteredIgnored {
	path := []map[string]string{}
	if ignore.Path != nil {
		for _, module := range *ignore.Path {
			// TODO: Validate if this is correct
			path = append(path, map[string]string{"module": module})
		}
	}

	ignoredBy := definitions.VulnFilteredIgnoredBy{
		// TODO: Validate if this is correct
		IsGroupPolicy: ignore.Source == "group",
	}
	if ignore.IgnoredBy != nil {
		ignoredBy.Id = ignore.IgnoredBy.Id.String()
		ignoredBy.Name = ignore.IgnoredBy.Name
		ignoredBy.Email = deref(ignore.IgnoredBy.Email, "")
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
