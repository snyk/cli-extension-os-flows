package transform

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"

	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	"github.com/snyk/cli-extension-os-flows/internal/util"
	"github.com/snyk/cli-extension-os-flows/pkg/localpolicy"
)

// LocalPolicyToSchema takes a policy from a .snyk file and transforms it to a list
// of LocalIgnore rules as defined by the snyk schema.
func LocalPolicyToSchema(lp *localpolicy.Policy) *[]testapi.LocalIgnore {
	if len(lp.Ignore) == 0 {
		return nil
	}

	var ignores []testapi.LocalIgnore

	for vulnID, entries := range lp.Ignore {
		for _, entry := range entries {
			for path := range entry {
				ignores = append(ignores, processLegacyRule(string(vulnID), path, entry[path]))
			}
		}
	}

	return &ignores
}

// ExtendLocalPolicyFromFindings extends a local policy with the given findings.
// If the given local policy is nil, a new policy will be created from scratch.
func ExtendLocalPolicyFromFindings(ctx context.Context, lp *localpolicy.Policy, findings []testapi.FindingData) (string, error) {
	logger := cmdctx.Logger(ctx)
	projectIgnores := make(map[string]*testapi.IgnoreDetails)

	for _, finding := range findings {
		vulnID, err := vulnIDFromFinding(&finding)
		if err != nil {
			return "", fmt.Errorf("failed to get vulnerability ID from finding: %w", err)
		}
		// If no vuln ID could be extracted from the finding, skip it.
		if vulnID == "" {
			logger.Warn().Msgf("finding has no snyk vulnerability ID: %s", finding.Id)
			continue
		}

		ignores, err := getIgnoresFromFinding(&finding)
		if err != nil {
			return "", fmt.Errorf("failed to transform ignores: %w", err)
		}
		for _, ignore := range ignores {
			projectIgnores[vulnID] = ignore
		}
	}

	if lp == nil {
		// If there is no local policy and there are no project-level ignores,
		// return an empty string.
		if len(projectIgnores) == 0 {
			return "", nil
		}

		lp = localpolicy.New()
	}

	for vulnID, ignore := range projectIgnores {
		lp.AddIgnore(localpolicy.VulnID(vulnID), util.DefaultValue(ignore.Path, nil), &localpolicy.Rule{
			Created:    ignore.Created,
			Expires:    ignore.Expires,
			Reason:     util.Ptr(ignore.Reason),
			ReasonType: (*localpolicy.ReasonType)(ignore.ReasonType),
			Source:     util.Ptr(ignore.Source),
			IgnoredBy: &localpolicy.IgnoredBy{
				ID:    util.Ptr(ignore.IgnoredBy.Id.String()),
				Name:  &ignore.IgnoredBy.Name,
				Email: ignore.IgnoredBy.Email,
			},
		})
	}

	var buf bytes.Buffer
	if err := localpolicy.Marshal(&buf, lp); err != nil {
		return "", fmt.Errorf("failed serializing local policy: %w", err)
	}

	return buf.String(), nil
}

func getIgnoresFromFinding(finding *testapi.FindingData) ([]*testapi.IgnoreDetails, error) {
	ignores := []*testapi.IgnoreDetails{}

	if finding.Attributes.Suppression == nil ||
		finding.Attributes.Suppression.Policy == nil ||
		finding.Relationships == nil ||
		finding.Relationships.Policy == nil {
		return ignores, nil
	}

	managedPolicyRef, err := finding.Attributes.Suppression.Policy.AsManagedPolicyRef()
	if err != nil {
		//nolint:nilerr // An error is expected for non-managed suppressions and can be swallowed here.
		return ignores, nil
	}

	// Go through related policies and find the applied one.
	for _, policy := range finding.Relationships.Policy.Data.Attributes.Policies {
		if managedPolicyRef.Id != policy.Id {
			continue
		}

		ignore, err := policy.AppliedPolicy.AsIgnore()
		if err != nil {
			return nil, fmt.Errorf("failed to build ignore from applied policy: %w", err)
		}

		ignores = append(ignores, &ignore.Ignore)
	}

	return ignores, nil
}

func vulnIDFromFinding(finding *testapi.FindingData) (string, error) {
	for _, problem := range finding.Attributes.Problems {
		dis, err := problem.Discriminator()
		if err != nil {
			return "", fmt.Errorf("failed to get problem discriminator: %w", err)
		}

		switch dis {
		default:
			continue
		case string(testapi.SnykVuln):
			prob, err := problem.AsSnykVulnProblem()
			if err != nil {
				return "", fmt.Errorf("failed to convert problem to snyk vuln problem: %w", err)
			}
			return prob.Id, nil
		case string(testapi.SnykLicense):
			prob, err := problem.AsSnykLicenseProblem()
			if err != nil {
				return "", fmt.Errorf("failed to convert problem to snyk license problem: %w", err)
			}
			return prob.Id, nil
		}
	}
	return "", nil
}

func processLegacyRule(vulnID, path string, rule *localpolicy.Rule) testapi.LocalIgnore {
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
