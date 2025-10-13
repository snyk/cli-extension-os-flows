package transform

import (
	"strings"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"

	"github.com/snyk/cli-extension-os-flows/internal/util"
	"github.com/snyk/cli-extension-os-flows/pkg/legacypolicy"
)

// LegacyPolicyToLocalPolicy takes a legacy policy from a .snyk file and
// transforms it to a list of LocalIgnore rules as defined by the snyk schema.
func LegacyPolicyToLocalPolicy(legacyPolicy *legacypolicy.Policy) (*[]testapi.LocalIgnore, error) {
	var ignores []testapi.LocalIgnore

	for vulnID, entries := range legacyPolicy.Ignore {
		for _, entry := range entries {
			for path := range entry {
				ignores = append(ignores, processLegacyRule(string(vulnID), path, entry[path]))
			}
		}
	}

	return &ignores, nil
}

func processLegacyRule(vulnID, path string, rule *legacypolicy.Rule) testapi.LocalIgnore {
	var splitPath *[]string
	if path != "*" {
		splitPath = util.Ptr(strings.Split(path, " > "))
	}

	return testapi.LocalIgnore{
		VulnId:    vulnID,
		Reason:    rule.Reason,
		Path:      splitPath,
		ExpiresAt: rule.Expires,
		CreatedAt: rule.Created,
	}
}
