package transform_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/legacy/definitions"
	"github.com/snyk/cli-extension-os-flows/internal/legacy/transform"
	legacyUtils "github.com/snyk/cli-extension-os-flows/internal/legacy/utils"
	"github.com/snyk/cli-extension-os-flows/internal/remediation"
	"github.com/snyk/cli-extension-os-flows/internal/util"
)

func Test_RemediationSummaryToLegacy(t *testing.T) {
	t.Run("empty remediation summary results in nil legacy summary", func(t *testing.T) {
		remSummary := remediation.Summary{}

		summary, err := transform.RemediationSummaryToLegacy([]definitions.Vulnerability{}, remSummary)
		require.NoError(t, err)

		assert.Nil(t, summary)
	})

	t.Run("remediation summary with pins results in valid legacy summary", func(t *testing.T) {
		remSummary := remediation.Summary{
			Pins: []*remediation.Upgrade{
				{
					From: newPackage("foo@1.0.0"),
					To:   newPackage("foo@1.2.0"),
					Fixes: []*remediation.VulnerabilityInPackage{
						{
							VulnerablePackage: newPackage("foo@1.0.0"),
							Vulnerability: remediation.Vulnerability{
								ID:       "SNYK-FOO-123",
								Name:     "SQL Injection",
								Severity: remediation.SeverityHigh,
							},
							FixedInVersions: []string{"1.1.0", "1.2.0", "2.0.0"},
							IntroducedThrough: []remediation.DependencyPath{
								newDependencyPath("root@0.0.0", "direct-1@1.0.0", "foo@1.0.0"),
								newDependencyPath("root@0.0.0", "direct-2@1.0.0", "foo@1.0.0"),
							},
						},
						{
							VulnerablePackage: newPackage("foo@1.0.0"),
							Vulnerability: remediation.Vulnerability{
								ID:       "SNYK-FOO-456",
								Name:     "Prompt injection",
								Severity: remediation.SeverityMedium,
							},
							FixedInVersions: []string{"1.2.0", "2.0.0"},
							IntroducedThrough: []remediation.DependencyPath{
								newDependencyPath("root@0.0.0", "direct-3@1.0.0", "foo@1.0.0"),
							},
						},
					},
				},
			},
		}

		summary, err := transform.RemediationSummaryToLegacy([]definitions.Vulnerability{}, remSummary)
		require.NoError(t, err)

		assert.Equal(t, &definitions.Remediation{
			Upgrade: map[string]definitions.RemediationUpgradeInfo{},
			Pin: map[string]definitions.PinRemediation{
				"foo@1.0.0": {
					IsTransitive: true,
					UpgradeTo:    "foo@1.2.0",
					Vulns:        []string{"SNYK-FOO-123", "SNYK-FOO-456"},
				},
			},
			Unresolved: []definitions.Vulnerability{},
		}, summary)
	})

	t.Run("remediation summary with upgrades results in valid legacy summary", func(t *testing.T) {
		remSummary := remediation.Summary{
			Upgrades: []*remediation.Upgrade{
				{
					From: newPackage("direct-1@1.0.0"),
					To:   newPackage("direct-1@1.2.0"),
					Fixes: []*remediation.VulnerabilityInPackage{
						{
							VulnerablePackage: newPackage("foo@1.0.0"),
							Vulnerability: remediation.Vulnerability{
								ID:       "SNYK-FOO-123",
								Name:     "SQL Injection",
								Severity: remediation.SeverityHigh,
							},
							FixedInVersions: []string{"1.1.0"},
							IntroducedThrough: []remediation.DependencyPath{
								newDependencyPath("root@0.0.0", "direct-1@1.0.0", "foo@1.0.0"),
								newDependencyPath("root@0.0.0", "direct-2@1.0.0", "foo@1.0.0"),
							},
						},
						{
							VulnerablePackage: newPackage("bar@1.0.0"),
							Vulnerability: remediation.Vulnerability{
								ID:       "SNYK-BAR-123",
								Name:     "Prompt Injection",
								Severity: remediation.SeverityLow,
							},
							FixedInVersions: []string{"1.2.0"},
							IntroducedThrough: []remediation.DependencyPath{
								newDependencyPath("root@0.0.0", "direct-1@1.0.0", "bar@1.0.0"),
							},
						},
					},
				},
				{
					From: newPackage("direct-2@1.0.0"),
					To:   newPackage("direct-2@2.0.0"),
					Fixes: []*remediation.VulnerabilityInPackage{
						{
							VulnerablePackage: newPackage("foo@1.0.0"),
							Vulnerability: remediation.Vulnerability{
								ID:       "SNYK-FOO-123",
								Name:     "SQL Injection",
								Severity: remediation.SeverityHigh,
							},
							FixedInVersions: []string{"1.1.0"},
							IntroducedThrough: []remediation.DependencyPath{
								newDependencyPath("root@0.0.0", "direct-1@1.0.0", "foo@1.0.0"),
								newDependencyPath("root@0.0.0", "direct-2@1.0.0", "foo@1.0.0"),
							},
						},
					},
				},
			},
		}

		summary, err := transform.RemediationSummaryToLegacy([]definitions.Vulnerability{}, remSummary)
		require.NoError(t, err)

		assert.Equal(t, &definitions.Remediation{
			Pin: map[string]definitions.PinRemediation{},
			Upgrade: map[string]definitions.RemediationUpgradeInfo{
				"direct-1@1.0.0": {
					UpgradeTo: "direct-1@1.2.0",
					Upgrades: []string{
						"foo@1.0.0",
						"bar@1.0.0",
					},
					Vulns: []string{"SNYK-FOO-123", "SNYK-BAR-123"},
				},
				"direct-2@1.0.0": {
					UpgradeTo: "direct-2@2.0.0",
					Upgrades: []string{
						"foo@1.0.0",
					},
					Vulns: []string{"SNYK-FOO-123"},
				},
			},
			Unresolved: []definitions.Vulnerability{},
		}, summary)
	})

	t.Run("remediation summary with unresolved results and missing vuln data results in an error", func(t *testing.T) {
		remSummary := remediation.Summary{
			Unresolved: []*remediation.VulnerabilityInPackage{
				{
					VulnerablePackage: newPackage("baz@1.0.0"),
					Vulnerability: remediation.Vulnerability{
						ID:       "SNYK-BAZ-123",
						Name:     "RCE",
						Severity: remediation.SeverityCritical,
					},
					FixedInVersions: []string{},
					IntroducedThrough: []remediation.DependencyPath{
						newDependencyPath("root@1.0.0", "direct-3@1.0.0", "baz@1.0.0"),
					},
				},
			},
		}

		_, err := transform.RemediationSummaryToLegacy([]definitions.Vulnerability{}, remSummary)

		assert.Error(t, err, "vulnerability not found in map")
	})

	t.Run("remediation summary with unresolved results in valid legacy summary", func(t *testing.T) {
		remSummary := remediation.Summary{
			Unresolved: []*remediation.VulnerabilityInPackage{
				{
					VulnerablePackage: newPackage("baz@1.0.0"),
					Vulnerability: remediation.Vulnerability{
						ID:       "SNYK-BAZ-123",
						Name:     "RCE",
						Severity: remediation.SeverityCritical,
					},
					FixedInVersions: []string{},
					IntroducedThrough: []remediation.DependencyPath{
						newDependencyPath("root@1.0.0", "direct-3@1.0.0", "baz@1.0.0"),
					},
				},
			},
		}
		unresolved := []definitions.Vulnerability{
			{
				Id:               "SNYK-BAZ-123",
				From:             []string{"root@1.0.0", "direct-3@1.0.0", "baz@1.0.0"},
				FixedIn:          &[]string{},
				PackageName:      util.Ptr("baz"),
				Version:          "1.0.0",
				IsUpgradable:     false,
				Reachability:     util.Ptr(definitions.Reachable),
				CvssScore:        util.Ptr(float32(9.7)),
				Severity:         definitions.Critical,
				ModificationTime: util.Ptr("2025-06-03T10:14:39Z"),
			},
		}

		summary, err := transform.RemediationSummaryToLegacy(unresolved, remSummary)
		require.NoError(t, err)

		assert.Equal(t, &definitions.Remediation{
			Pin:        map[string]definitions.PinRemediation{},
			Upgrade:    map[string]definitions.RemediationUpgradeInfo{},
			Unresolved: unresolved,
		}, summary)
	})

	t.Run("remediation summary with unresolved and upgrade for the same vuln results in valid legacy summary", func(t *testing.T) {
		remSummary := remediation.Summary{
			Upgrades: []*remediation.Upgrade{
				{
					From: newPackage("direct-1@1.0.0"),
					To:   newPackage("direct-1@1.2.0"),
					Fixes: []*remediation.VulnerabilityInPackage{
						{
							VulnerablePackage: newPackage("foo@1.0.0"),
							Vulnerability: remediation.Vulnerability{
								ID:       "SNYK-FOO-123",
								Name:     "SQL Injection",
								Severity: remediation.SeverityHigh,
							},
							FixedInVersions: []string{},
							IntroducedThrough: []remediation.DependencyPath{
								newDependencyPath("root@1.0.0", "direct-1@1.0.0", "foo@1.0.0"),
							},
						},
					},
				},
			},
			Unresolved: []*remediation.VulnerabilityInPackage{
				{
					VulnerablePackage: newPackage("foo@1.0.0"),
					Vulnerability: remediation.Vulnerability{
						ID:       "SNYK-FOO-123",
						Name:     "SQL Injection",
						Severity: remediation.SeverityHigh,
					},
					FixedInVersions: []string{},
					IntroducedThrough: []remediation.DependencyPath{
						newDependencyPath("root@1.0.0", "foo@1.0.0"),
					},
				},
			},
		}
		// We consider the issue unresolved for this path, as pkg `foo` doesn't have an upgrade
		unresolved := []definitions.Vulnerability{
			{
				Id:               "SNYK-FOO-123",
				From:             []string{"root@1.0.0", "foo@1.0.0"},
				IsUpgradable:     false,
				FixedIn:          &[]string{},
				PackageName:      util.Ptr("foo"),
				Version:          "1.0.0",
				Reachability:     util.Ptr(definitions.Reachable),
				CvssScore:        util.Ptr(float32(9.7)),
				Severity:         definitions.High,
				ModificationTime: util.Ptr("2025-06-03T10:14:39Z"),
			},
		}
		var allIssues []definitions.Vulnerability
		allIssues = append(allIssues, unresolved...)

		root := definitions.Vulnerability_UpgradePath_Item{}
		err := root.FromVulnerabilityUpgradePath1(false)
		require.NoError(t, err)
		dep := definitions.Vulnerability_UpgradePath_Item{}
		err = dep.FromVulnerabilityUpgradePath0("direct-1@1.2.0")
		require.NoError(t, err)

		// We consider the same issue resolved here, as upgrading pkg `direct-1`
		// will result in us dropping the `foo` dependency
		uPath := []definitions.Vulnerability_UpgradePath_Item{root, dep}
		allIssues = append(allIssues, definitions.Vulnerability{
			Id:               "SNYK-FOO-123",
			From:             []string{"root@1.0.0", "direct-1@1.0.0", "foo@1.0.0"},
			IsUpgradable:     true,
			UpgradePath:      uPath,
			FixedIn:          &[]string{},
			PackageName:      util.Ptr("foo"),
			Version:          "1.0.0",
			Reachability:     util.Ptr(definitions.Reachable),
			CvssScore:        util.Ptr(float32(9.7)),
			Severity:         definitions.High,
			ModificationTime: util.Ptr("2025-06-03T10:14:39Z"),
		})

		summary, err := transform.RemediationSummaryToLegacy(allIssues, remSummary)
		require.NoError(t, err)

		assert.Equal(t, &definitions.Remediation{
			Pin: map[string]definitions.PinRemediation{},
			Upgrade: map[string]definitions.RemediationUpgradeInfo{
				"direct-1@1.0.0": {
					UpgradeTo: "direct-1@1.2.0",
					Upgrades:  []string{"foo@1.0.0"},
					Vulns:     []string{"SNYK-FOO-123"},
				},
			},
			Unresolved: unresolved,
		}, summary)
	})
}

// Utils.
func newPackage(p string) remediation.Package {
	name, version := legacyUtils.SplitNameAndVersion(p)
	return remediation.Package{Name: name, Version: version}
}

func newDependencyPath(p ...string) remediation.DependencyPath {
	var output remediation.DependencyPath
	for _, s := range p {
		output = append(output, newPackage(s))
	}
	return output
}
