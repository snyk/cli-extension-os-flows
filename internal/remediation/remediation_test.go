package remediation_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	legacyUtils "github.com/snyk/cli-extension-os-flows/internal/legacy/utils"
	"github.com/snyk/cli-extension-os-flows/internal/remediation"
)

func Test_FindingsToRemediationSummary(t *testing.T) {
	t.Run("no findings returns empty summary", func(t *testing.T) {
		summary, err := remediation.FindingsToRemediationSummary([]*remediation.Finding{})

		require.NoError(t, err)
		equalSummaries(t, remediation.Summary{}, summary)
	})

	t.Run("pins", func(t *testing.T) {
		// Since pins are meant to hoist the vulnerable version to the fixed one, there won't be leftover paths on the
		// vulnerable version, thus, pins can only be fully resolved fixes.
		t.Run("fully resolved (only possible scenario for pins today)", func(t *testing.T) {
			t.Run("single pin for single package returns valid summary", func(t *testing.T) {
				summary, err := remediation.FindingsToRemediationSummary([]*remediation.Finding{
					{
						Vulnerability: aVulnerabilityWithID("VULN_ID"),
						Package:       newPackage("vulnerable@1.0.0"),
						DependencyPaths: []remediation.DependencyPath{
							newDependencyPath("root@1.0.0", "direct@1.0.0", "vulnerable@1.0.0"),
						},
						FixedInVersions: []string{"1.0.1", "2.0.0"},
						PackageManager:  "pip",
						Fix: remediation.NewPinFix(remediation.FullyResolved,
							remediation.PinAction{
								Package: newPackage("vulnerable@1.0.1"),
							},
						),
					},
				})
				require.NoError(t, err)
				equalSummaries(t, remediation.Summary{
					Pins: []*remediation.Upgrade{{
						From: newPackage("vulnerable@1.0.0"),
						To:   newPackage("vulnerable@1.0.1"),
						Fixes: []*remediation.VulnerabilityInPackage{{
							FixedInVersions:   []string{"1.0.1", "2.0.0"},
							VulnerablePackage: newPackage("vulnerable@1.0.0"),
							Vulnerability:     aVulnerabilityWithID("VULN_ID"),
							IntroducedThrough: []remediation.DependencyPath{
								newDependencyPath("root@1.0.0", "direct@1.0.0", "vulnerable@1.0.0"),
							},
						}},
					}},
				}, summary)
			})

			t.Run("two pins for two different packages returns valid summary", func(t *testing.T) {
				summary, err := remediation.FindingsToRemediationSummary([]*remediation.Finding{
					{
						Vulnerability: aVulnerabilityWithID("VULN_ID_1"),
						Package:       newPackage("vulnerable@1.0.0"),
						DependencyPaths: []remediation.DependencyPath{
							newDependencyPath("root@1.0.0", "direct@1.0.0", "vulnerable@1.0.0"),
						},
						FixedInVersions: []string{"1.0.1", "2.0.0"},
						PackageManager:  "pip",
						Fix: remediation.NewPinFix(remediation.FullyResolved,
							remediation.PinAction{
								Package: newPackage("vulnerable@1.0.1"),
							},
						),
					},
					{
						Vulnerability: aVulnerabilityWithID("VULN_ID_2"),
						Package:       newPackage("vulnerable-2@1.0.0"),
						DependencyPaths: []remediation.DependencyPath{
							newDependencyPath("root@1.0.0", "direct@1.0.0", "vulnerable-2@1.0.0"),
						},
						FixedInVersions: []string{"1.0.2", "2.0.1"},
						PackageManager:  "pip",
						Fix: remediation.NewPinFix(remediation.FullyResolved,
							remediation.PinAction{
								Package: newPackage("vulnerable-2@1.0.2"),
							},
						),
					},
				})
				require.NoError(t, err)
				equalSummaries(t, remediation.Summary{
					Pins: []*remediation.Upgrade{{
						From: newPackage("vulnerable@1.0.0"),
						To:   newPackage("vulnerable@1.0.1"),
						Fixes: []*remediation.VulnerabilityInPackage{{
							FixedInVersions:   []string{"1.0.1", "2.0.0"},
							VulnerablePackage: newPackage("vulnerable@1.0.0"),
							Vulnerability:     aVulnerabilityWithID("VULN_ID_1"),
							IntroducedThrough: []remediation.DependencyPath{
								newDependencyPath("root@1.0.0", "direct@1.0.0", "vulnerable@1.0.0"),
							},
						}},
					}, {
						From: newPackage("vulnerable-2@1.0.0"),
						To:   newPackage("vulnerable-2@1.0.2"),
						Fixes: []*remediation.VulnerabilityInPackage{{
							FixedInVersions:   []string{"1.0.2", "2.0.1"},
							VulnerablePackage: newPackage("vulnerable-2@1.0.0"),
							Vulnerability:     aVulnerabilityWithID("VULN_ID_2"),
							IntroducedThrough: []remediation.DependencyPath{
								newDependencyPath("root@1.0.0", "direct@1.0.0", "vulnerable-2@1.0.0"),
							},
						}},
					}},
				}, summary)
			})

			t.Run("a pin with multiple dependency path returns valid summary", func(t *testing.T) {
				summary, err := remediation.FindingsToRemediationSummary([]*remediation.Finding{
					{
						Vulnerability: aVulnerabilityWithID("VULN_ID"),
						Package:       newPackage("vulnerable@1.0.0"),
						DependencyPaths: []remediation.DependencyPath{
							newDependencyPath("root@1.0.0", "direct@1.0.0", "vulnerable@1.0.0"),
							newDependencyPath("root@1.0.0", "direct-2@1.0.0", "vulnerable@1.0.0"),
						},
						FixedInVersions: []string{"1.0.1", "2.0.0"},
						PackageManager:  "pip",
						Fix: remediation.NewPinFix(remediation.FullyResolved,
							remediation.PinAction{
								Package: newPackage("vulnerable@1.0.1"),
							},
						),
					},
				})
				require.NoError(t, err)
				equalSummaries(t, remediation.Summary{
					Pins: []*remediation.Upgrade{{
						From: newPackage("vulnerable@1.0.0"),
						To:   newPackage("vulnerable@1.0.1"),
						Fixes: []*remediation.VulnerabilityInPackage{{
							FixedInVersions:   []string{"1.0.1", "2.0.0"},
							VulnerablePackage: newPackage("vulnerable@1.0.0"),
							Vulnerability:     aVulnerabilityWithID("VULN_ID"),
							IntroducedThrough: []remediation.DependencyPath{
								newDependencyPath("root@1.0.0", "direct@1.0.0", "vulnerable@1.0.0"),
								newDependencyPath("root@1.0.0", "direct-2@1.0.0", "vulnerable@1.0.0"),
							},
						}},
					}},
				}, summary)
			})

			t.Run("two pins for the same package with the same version but different vulns", func(t *testing.T) {
				summary, err := remediation.FindingsToRemediationSummary([]*remediation.Finding{
					{
						Vulnerability: aVulnerabilityWithID("VULN_ID_1"),
						Package:       newPackage("vulnerable@1.0.0"),
						DependencyPaths: []remediation.DependencyPath{
							newDependencyPath("root@1.0.0", "direct@1.0.0", "vulnerable@1.0.0"),
						},
						FixedInVersions: []string{"1.0.1", "2.0.0"},
						PackageManager:  "pip",
						Fix: remediation.NewPinFix(remediation.FullyResolved,
							remediation.PinAction{
								Package: newPackage("vulnerable@1.0.1"),
							},
						),
					},
					{
						Vulnerability: aVulnerabilityWithID("VULN_ID_2"),
						Package:       newPackage("vulnerable@1.0.0"),
						DependencyPaths: []remediation.DependencyPath{
							newDependencyPath("root@1.0.0", "direct@1.0.0", "vulnerable@1.0.0"),
						},
						FixedInVersions: []string{"1.0.2", "2.0.1"},
						PackageManager:  "pip",
						Fix: remediation.NewPinFix(remediation.FullyResolved,
							remediation.PinAction{
								Package: newPackage("vulnerable@1.0.2"),
							},
						),
					},
				})
				require.NoError(t, err)
				equalSummaries(t, remediation.Summary{
					Pins: []*remediation.Upgrade{{
						From: newPackage("vulnerable@1.0.0"),
						To:   newPackage("vulnerable@1.0.2"),
						Fixes: []*remediation.VulnerabilityInPackage{{
							FixedInVersions:   []string{"1.0.1", "2.0.0"},
							VulnerablePackage: newPackage("vulnerable@1.0.0"),
							Vulnerability:     aVulnerabilityWithID("VULN_ID_1"),
							IntroducedThrough: []remediation.DependencyPath{
								newDependencyPath("root@1.0.0", "direct@1.0.0", "vulnerable@1.0.0"),
							},
						}, {
							FixedInVersions:   []string{"1.0.2", "2.0.1"},
							VulnerablePackage: newPackage("vulnerable@1.0.0"),
							Vulnerability:     aVulnerabilityWithID("VULN_ID_2"),
							IntroducedThrough: []remediation.DependencyPath{
								newDependencyPath("root@1.0.0", "direct@1.0.0", "vulnerable@1.0.0"),
							},
						}},
					}},
				}, summary)
			})

			t.Run("two pins for the same package with the same vuln but different versions create two pins", func(t *testing.T) {
				summary, err := remediation.FindingsToRemediationSummary([]*remediation.Finding{
					{
						Vulnerability: aVulnerabilityWithID("VULN_ID_1"),
						Package:       newPackage("vulnerable@1.0.0"),
						DependencyPaths: []remediation.DependencyPath{
							newDependencyPath("root@1.0.0", "direct@1.0.0", "vulnerable@1.0.0"),
						},
						FixedInVersions: []string{"1.0.1", "2.0.1"},
						PackageManager:  "pip",
						Fix: remediation.NewPinFix(remediation.FullyResolved,
							remediation.PinAction{
								Package: newPackage("vulnerable@1.0.1"),
							},
						),
					},
					{
						Vulnerability: aVulnerabilityWithID("VULN_ID_1"),
						Package:       newPackage("vulnerable@2.0.0"),
						DependencyPaths: []remediation.DependencyPath{
							newDependencyPath("root@1.0.0", "direct-2@1.0.0", "vulnerable@2.0.0"),
						},
						FixedInVersions: []string{"1.0.1", "2.0.1"},
						PackageManager:  "pip",
						Fix: remediation.NewPinFix(remediation.FullyResolved,
							remediation.PinAction{
								Package: newPackage("vulnerable@2.0.1"),
							},
						),
					},
				})
				require.NoError(t, err)
				equalSummaries(t, remediation.Summary{
					Pins: []*remediation.Upgrade{{
						From: newPackage("vulnerable@1.0.0"),
						To:   newPackage("vulnerable@2.0.1"),
						Fixes: []*remediation.VulnerabilityInPackage{{
							FixedInVersions:   []string{"1.0.1", "2.0.1"},
							VulnerablePackage: newPackage("vulnerable@1.0.0"),
							Vulnerability:     aVulnerabilityWithID("VULN_ID_1"),
							IntroducedThrough: []remediation.DependencyPath{
								newDependencyPath("root@1.0.0", "direct@1.0.0", "vulnerable@1.0.0"),
							},
						}},
					}, {
						From: newPackage("vulnerable@2.0.0"),
						To:   newPackage("vulnerable@2.0.1"),
						Fixes: []*remediation.VulnerabilityInPackage{{
							FixedInVersions:   []string{"1.0.1", "2.0.1"},
							VulnerablePackage: newPackage("vulnerable@2.0.0"),
							Vulnerability:     aVulnerabilityWithID("VULN_ID_1"),
							IntroducedThrough: []remediation.DependencyPath{
								newDependencyPath("root@1.0.0", "direct-2@1.0.0", "vulnerable@2.0.0"),
							},
						}},
					}},
				}, summary)
			})
		})
	})

	t.Run("upgrades", func(t *testing.T) {
		t.Run("upgrade for single package with single path returns valid summary", func(t *testing.T) {
			summary, err := remediation.FindingsToRemediationSummary([]*remediation.Finding{
				{
					Vulnerability: aVulnerabilityWithID("VULN_ID"),
					Package:       newPackage("vulnerable@1.0.0"),
					DependencyPaths: []remediation.DependencyPath{
						newDependencyPath("root@1.0.0", "direct@1.0.0", "vulnerable@1.0.0"),
					},
					FixedInVersions: []string{"1.0.1", "2.0.0"},
					PackageManager:  "npm",
					Fix: remediation.NewUpgradeFix(remediation.FullyResolved, remediation.UpgradeAction{
						PackageName: "vulnerable",
						UpgradePaths: []remediation.DependencyPath{
							newDependencyPath("root@1.0.0", "direct@1.2.3", "vulnerable@1.0.1"),
						},
					}),
				},
			})

			require.NoError(t, err)
			equalSummaries(t, remediation.Summary{
				Upgrades: []*remediation.Upgrade{
					{
						From: newPackage("direct@1.0.0"),
						To:   newPackage("direct@1.2.3"),
						Fixes: []*remediation.VulnerabilityInPackage{
							{
								FixedInVersions:   []string{"1.0.1", "2.0.0"},
								VulnerablePackage: newPackage("vulnerable@1.0.0"),
								Vulnerability:     aVulnerabilityWithID("VULN_ID"),
								IntroducedThrough: []remediation.DependencyPath{
									newDependencyPath("root@1.0.0", "direct@1.0.0", "vulnerable@1.0.0"),
								},
							},
						},
					},
				},
			}, summary)
		})

		t.Run("upgrades for single package with multiple resolved paths returns valid summary", func(t *testing.T) {
			summary, err := remediation.FindingsToRemediationSummary([]*remediation.Finding{
				{
					Vulnerability: aVulnerabilityWithID("VULN_ID"),
					Package:       newPackage("vulnerable@1.0.0"),
					DependencyPaths: []remediation.DependencyPath{
						newDependencyPath("root@1.0.0", "direct-1@1.0.0", "vulnerable@1.0.0"),
						newDependencyPath("root@1.0.0", "direct-2@1.0.0", "vulnerable@1.0.0"),
					},
					FixedInVersions: []string{"1.0.1", "2.0.0"},
					PackageManager:  "npm",
					Fix: remediation.NewUpgradeFix(remediation.FullyResolved, remediation.UpgradeAction{
						PackageName: "vulnerable",
						UpgradePaths: []remediation.DependencyPath{
							newDependencyPath("root@1.0.0", "direct-1@1.2.3", "vulnerable@1.0.1"),
							newDependencyPath("root@1.0.0", "direct-2@1.0.5", "vulnerable@1.0.1"),
						},
					}),
				},
			})

			require.NoError(t, err)
			equalSummaries(t, remediation.Summary{
				Upgrades: []*remediation.Upgrade{
					{
						From: newPackage("direct-1@1.0.0"),
						To:   newPackage("direct-1@1.2.3"),
						Fixes: []*remediation.VulnerabilityInPackage{
							{
								FixedInVersions:   []string{"1.0.1", "2.0.0"},
								VulnerablePackage: newPackage("vulnerable@1.0.0"),
								Vulnerability:     aVulnerabilityWithID("VULN_ID"),
								IntroducedThrough: []remediation.DependencyPath{
									newDependencyPath("root@1.0.0", "direct-1@1.0.0", "vulnerable@1.0.0"),
									newDependencyPath("root@1.0.0", "direct-2@1.0.0", "vulnerable@1.0.0"),
								},
							},
						},
					},
					{
						From: newPackage("direct-2@1.0.0"),
						To:   newPackage("direct-2@1.0.5"),
						Fixes: []*remediation.VulnerabilityInPackage{
							{
								FixedInVersions:   []string{"1.0.1", "2.0.0"},
								VulnerablePackage: newPackage("vulnerable@1.0.0"),
								Vulnerability:     aVulnerabilityWithID("VULN_ID"),
								IntroducedThrough: []remediation.DependencyPath{
									newDependencyPath("root@1.0.0", "direct-1@1.0.0", "vulnerable@1.0.0"),
									newDependencyPath("root@1.0.0", "direct-2@1.0.0", "vulnerable@1.0.0"),
								},
							},
						},
					},
				},
			}, summary)
		})

		t.Run("upgrades for single package with multiple resolved paths (different length / shuffled arrays) returns valid summary", func(t *testing.T) {
			summary, err := remediation.FindingsToRemediationSummary([]*remediation.Finding{
				{
					Vulnerability: aVulnerabilityWithID("VULN_ID"),
					Package:       newPackage("vulnerable@1.0.0"),
					DependencyPaths: []remediation.DependencyPath{
						newDependencyPath("root@1.0.0", "direct-1@1.0.0", "vulnerable@1.0.0"),
						newDependencyPath("root@1.0.0", "direct-2@1.0.0", "transitive-1@1.0.0", "vulnerable@1.0.0"),
					},
					FixedInVersions: []string{"1.0.1", "2.0.0"},
					PackageManager:  "npm",
					Fix: remediation.NewUpgradeFix(remediation.FullyResolved, remediation.UpgradeAction{
						PackageName: "vulnerable",
						UpgradePaths: []remediation.DependencyPath{
							newDependencyPath("root@1.0.0", "direct-2@1.0.5", "transitive-1@1.0.4", "vulnerable@1.0.1"),
							newDependencyPath("root@1.0.0", "direct-1@1.2.3", "vulnerable@1.0.1"),
						},
					}),
				},
			})

			require.NoError(t, err)
			equalSummaries(t, remediation.Summary{
				Upgrades: []*remediation.Upgrade{
					{
						From: newPackage("direct-1@1.0.0"),
						To:   newPackage("direct-1@1.2.3"),
						Fixes: []*remediation.VulnerabilityInPackage{
							{
								FixedInVersions:   []string{"1.0.1", "2.0.0"},
								VulnerablePackage: newPackage("vulnerable@1.0.0"),
								Vulnerability:     aVulnerabilityWithID("VULN_ID"),
								IntroducedThrough: []remediation.DependencyPath{
									newDependencyPath("root@1.0.0", "direct-1@1.0.0", "vulnerable@1.0.0"),
									newDependencyPath("root@1.0.0", "direct-2@1.0.0", "transitive-1@1.0.0", "vulnerable@1.0.0"),
								},
							},
						},
					},
					{
						From: newPackage("direct-2@1.0.0"),
						To:   newPackage("direct-2@1.0.5"),
						Fixes: []*remediation.VulnerabilityInPackage{
							{
								FixedInVersions:   []string{"1.0.1", "2.0.0"},
								VulnerablePackage: newPackage("vulnerable@1.0.0"),
								Vulnerability:     aVulnerabilityWithID("VULN_ID"),
								IntroducedThrough: []remediation.DependencyPath{
									newDependencyPath("root@1.0.0", "direct-1@1.0.0", "vulnerable@1.0.0"),
									newDependencyPath("root@1.0.0", "direct-2@1.0.0", "transitive-1@1.0.0", "vulnerable@1.0.0"),
								},
							},
						},
					},
				},
			}, summary)
		})

		t.Run("upgrade for single package with an unresolved path and a resolved path returns upgrade and unresolved summary entry", func(t *testing.T) {
			summary, err := remediation.FindingsToRemediationSummary([]*remediation.Finding{
				{
					Vulnerability: aVulnerabilityWithID("VULN_ID"),
					Package:       newPackage("vulnerable@1.0.0"),
					DependencyPaths: []remediation.DependencyPath{
						newDependencyPath("root@1.0.0", "direct-1@1.0.0", "vulnerable@1.0.0"),
						newDependencyPath("root@1.0.0", "direct-2@1.0.0", "transitive-1@1.0.0", "vulnerable@1.0.0"),
					},
					FixedInVersions: []string{"1.0.1", "2.0.0"},
					PackageManager:  "npm",
					Fix: remediation.NewUpgradeFix(remediation.FullyResolved, remediation.UpgradeAction{
						PackageName: "vulnerable",
						UpgradePaths: []remediation.DependencyPath{
							newDependencyPath("root@1.0.0", "direct-1@1.2.3", "vulnerable@1.0.1"),
						},
					}),
				},
			})

			require.NoError(t, err)
			equalSummaries(t, remediation.Summary{
				Upgrades: []*remediation.Upgrade{
					{
						From: newPackage("direct-1@1.0.0"),
						To:   newPackage("direct-1@1.2.3"),
						Fixes: []*remediation.VulnerabilityInPackage{
							{
								FixedInVersions:   []string{"1.0.1", "2.0.0"},
								VulnerablePackage: newPackage("vulnerable@1.0.0"),
								Vulnerability:     aVulnerabilityWithID("VULN_ID"),
								IntroducedThrough: []remediation.DependencyPath{
									newDependencyPath("root@1.0.0", "direct-1@1.0.0", "vulnerable@1.0.0"),
								},
							},
						},
					},
				},
				Unresolved: []*remediation.VulnerabilityInPackage{
					{
						FixedInVersions:   []string{"1.0.1", "2.0.0"},
						VulnerablePackage: newPackage("vulnerable@1.0.0"),
						Vulnerability:     aVulnerabilityWithID("VULN_ID"),
						IntroducedThrough: []remediation.DependencyPath{
							newDependencyPath("root@1.0.0", "direct-2@1.0.0", "transitive-1@1.0.0", "vulnerable@1.0.0"),
						},
					},
				},
			}, summary)
		})

		t.Run("upgrade for single package with multiple vulns returns valid summary", func(t *testing.T) {
			summary, err := remediation.FindingsToRemediationSummary([]*remediation.Finding{
				{
					Vulnerability: aVulnerabilityWithID("VULN_ID"),
					Package:       newPackage("vulnerable@1.0.0"),
					DependencyPaths: []remediation.DependencyPath{
						newDependencyPath("root@1.0.0", "direct@1.0.0", "vulnerable@1.0.0"),
					},
					FixedInVersions: []string{"1.0.1", "2.0.0"},
					PackageManager:  "npm",
					Fix: remediation.NewUpgradeFix(remediation.FullyResolved, remediation.UpgradeAction{
						PackageName: "vulnerable",
						UpgradePaths: []remediation.DependencyPath{
							newDependencyPath("root@1.0.0", "direct@1.2.3", "vulnerable@1.0.1"),
						},
					}),
				},
				{
					Vulnerability: aVulnerabilityWithID("VULN_ID_2"),
					Package:       newPackage("vulnerable@1.0.0"),
					DependencyPaths: []remediation.DependencyPath{
						newDependencyPath("root@1.0.0", "direct@1.0.0", "vulnerable@1.0.0"),
					},
					FixedInVersions: []string{"1.0.1", "2.0.0"},
					PackageManager:  "npm",
					Fix: remediation.NewUpgradeFix(remediation.FullyResolved, remediation.UpgradeAction{
						PackageName: "vulnerable",
						UpgradePaths: []remediation.DependencyPath{
							newDependencyPath("root@1.0.0", "direct@1.2.3", "vulnerable@1.0.1"),
						},
					}),
				},
			})

			require.NoError(t, err)
			equalSummaries(t, remediation.Summary{
				Upgrades: []*remediation.Upgrade{
					{
						From: newPackage("direct@1.0.0"),
						To:   newPackage("direct@1.2.3"),
						Fixes: []*remediation.VulnerabilityInPackage{
							{
								FixedInVersions:   []string{"1.0.1", "2.0.0"},
								VulnerablePackage: newPackage("vulnerable@1.0.0"),
								Vulnerability:     aVulnerabilityWithID("VULN_ID"),
								IntroducedThrough: []remediation.DependencyPath{
									newDependencyPath("root@1.0.0", "direct@1.0.0", "vulnerable@1.0.0"),
								},
							},
							{
								FixedInVersions:   []string{"1.0.1", "2.0.0"},
								VulnerablePackage: newPackage("vulnerable@1.0.0"),
								Vulnerability:     aVulnerabilityWithID("VULN_ID_2"),
								IntroducedThrough: []remediation.DependencyPath{
									newDependencyPath("root@1.0.0", "direct@1.0.0", "vulnerable@1.0.0"),
								},
							},
						},
					},
				},
			}, summary)
		})

		t.Run("upgrade for multiple packages with multiple vulns returns valid summary", func(t *testing.T) {
			summary, err := remediation.FindingsToRemediationSummary([]*remediation.Finding{
				{
					Vulnerability: aVulnerabilityWithID("VULN_ID_1"),
					Package:       newPackage("vulnerable-1@1.0.0"),
					DependencyPaths: []remediation.DependencyPath{
						newDependencyPath("root@1.0.0", "direct@1.0.0", "vulnerable-1@1.0.0"),
					},
					FixedInVersions: []string{"1.0.1", "2.0.0"},
					PackageManager:  "npm",
					Fix: remediation.NewUpgradeFix(remediation.FullyResolved, remediation.UpgradeAction{
						PackageName: "vulnerable-1",
						UpgradePaths: []remediation.DependencyPath{
							newDependencyPath("root@1.0.0", "direct@1.2.3", "vulnerable-1@1.0.1"),
						},
					}),
				},
				{
					Vulnerability: aVulnerabilityWithID("VULN_ID_2"),
					Package:       newPackage("vulnerable-2@1.0.0"),
					DependencyPaths: []remediation.DependencyPath{
						newDependencyPath("root@1.0.0", "direct@1.0.0", "vulnerable-2@1.0.0"),
					},
					FixedInVersions: []string{"1.0.1", "2.0.0"},
					PackageManager:  "npm",
					Fix: remediation.NewUpgradeFix(remediation.FullyResolved, remediation.UpgradeAction{
						PackageName: "vulnerable-2",
						UpgradePaths: []remediation.DependencyPath{
							newDependencyPath("root@1.0.0", "direct@1.4.0", "vulnerable-2@1.0.1"),
						},
					}),
				},
			})

			require.NoError(t, err)
			equalSummaries(t, remediation.Summary{
				Upgrades: []*remediation.Upgrade{
					{
						From: newPackage("direct@1.0.0"),
						To:   newPackage("direct@1.4.0"),
						Fixes: []*remediation.VulnerabilityInPackage{
							{
								FixedInVersions:   []string{"1.0.1", "2.0.0"},
								VulnerablePackage: newPackage("vulnerable-1@1.0.0"),
								Vulnerability:     aVulnerabilityWithID("VULN_ID_1"),
								IntroducedThrough: []remediation.DependencyPath{
									newDependencyPath("root@1.0.0", "direct@1.0.0", "vulnerable-1@1.0.0"),
								},
							},
							{
								FixedInVersions:   []string{"1.0.1", "2.0.0"},
								VulnerablePackage: newPackage("vulnerable-2@1.0.0"),
								Vulnerability:     aVulnerabilityWithID("VULN_ID_2"),
								IntroducedThrough: []remediation.DependencyPath{
									newDependencyPath("root@1.0.0", "direct@1.0.0", "vulnerable-2@1.0.0"),
								},
							},
						},
					},
				},
			}, summary)
		})

		t.Run("upgrades for multiple packages with multiple vulns returns valid summary", func(t *testing.T) {
			summary, err := remediation.FindingsToRemediationSummary([]*remediation.Finding{
				{
					Vulnerability: aVulnerabilityWithID("VULN_ID_1"),
					Package:       newPackage("vulnerable-1@1.0.0"),
					DependencyPaths: []remediation.DependencyPath{
						newDependencyPath("root@1.0.0", "direct-1@1.0.0", "vulnerable-1@1.0.0"),
					},
					FixedInVersions: []string{"1.0.1", "2.0.0"},
					PackageManager:  "npm",
					Fix: remediation.NewUpgradeFix(remediation.FullyResolved, remediation.UpgradeAction{
						PackageName: "vulnerable-1",
						UpgradePaths: []remediation.DependencyPath{
							newDependencyPath("root@1.0.0", "direct-1@1.2.3", "vulnerable-1@1.0.1"),
						},
					}),
				},
				{
					Vulnerability: aVulnerabilityWithID("VULN_ID_2"),
					Package:       newPackage("vulnerable-2@1.0.0"),
					DependencyPaths: []remediation.DependencyPath{
						newDependencyPath("root@1.0.0", "direct-2@1.0.0", "vulnerable-2@1.0.0"),
					},
					FixedInVersions: []string{"1.0.1", "2.0.0"},
					PackageManager:  "npm",
					Fix: remediation.NewUpgradeFix(remediation.FullyResolved, remediation.UpgradeAction{
						PackageName: "vulnerable-2",
						UpgradePaths: []remediation.DependencyPath{
							newDependencyPath("root@1.0.0", "direct-2@1.4.0", "vulnerable-2@1.0.1"),
						},
					}),
				},
			})

			require.NoError(t, err)
			equalSummaries(t, remediation.Summary{
				Upgrades: []*remediation.Upgrade{
					{
						From: newPackage("direct-1@1.0.0"),
						To:   newPackage("direct-1@1.2.3"),
						Fixes: []*remediation.VulnerabilityInPackage{
							{
								FixedInVersions:   []string{"1.0.1", "2.0.0"},
								VulnerablePackage: newPackage("vulnerable-1@1.0.0"),
								Vulnerability:     aVulnerabilityWithID("VULN_ID_1"),
								IntroducedThrough: []remediation.DependencyPath{
									newDependencyPath("root@1.0.0", "direct-1@1.0.0", "vulnerable-1@1.0.0"),
								},
							},
						},
					},
					{
						From: newPackage("direct-2@1.0.0"),
						To:   newPackage("direct-2@1.4.0"),
						Fixes: []*remediation.VulnerabilityInPackage{
							{
								FixedInVersions:   []string{"1.0.1", "2.0.0"},
								VulnerablePackage: newPackage("vulnerable-2@1.0.0"),
								Vulnerability:     aVulnerabilityWithID("VULN_ID_2"),
								IntroducedThrough: []remediation.DependencyPath{
									newDependencyPath("root@1.0.0", "direct-2@1.0.0", "vulnerable-2@1.0.0"),
								},
							},
						},
					},
				},
			}, summary)
		})
	})

	t.Run("unresolved", func(t *testing.T) {
		t.Run("a finding containing no fix action returns valid summary", func(t *testing.T) {
			summary, err := remediation.FindingsToRemediationSummary([]*remediation.Finding{
				{
					Vulnerability: aVulnerabilityWithID("VULN_ID"),
					Package:       newPackage("vulnerable@1.0.0"),
					DependencyPaths: []remediation.DependencyPath{
						newDependencyPath("root@1.0.0", "direct-1@1.0.0", "vulnerable@1.0.0"),
					},
					FixedInVersions: []string{"1.0.1", "2.0.0"},
					PackageManager:  "npm",
					Fix:             remediation.NewUnresolvedFix(),
				},
			})

			require.NoError(t, err)
			equalSummaries(t, remediation.Summary{
				Unresolved: []*remediation.VulnerabilityInPackage{
					{
						FixedInVersions:   []string{"1.0.1", "2.0.0"},
						VulnerablePackage: newPackage("vulnerable@1.0.0"),
						Vulnerability:     aVulnerabilityWithID("VULN_ID"),
						IntroducedThrough: []remediation.DependencyPath{
							newDependencyPath("root@1.0.0", "direct-1@1.0.0", "vulnerable@1.0.0"),
						},
					},
				},
			}, summary)
		})
	})
}

func aVulnerabilityWithID(vulnID remediation.VulnID) remediation.Vulnerability {
	return remediation.Vulnerability{
		ID:       vulnID,
		Name:     "a vuln",
		Severity: remediation.SeverityHigh,
	}
}

func equalSummaries(t *testing.T, expected, actual remediation.Summary) {
	t.Helper()

	equalUpgrades(t, expected.Pins, actual.Pins)
	equalUpgrades(t, expected.Upgrades, actual.Upgrades)
	equalVulnerabilityInPackages(t, expected.Unresolved, actual.Unresolved)
}

func equalUpgrades(t *testing.T, expected, actual []*remediation.Upgrade) {
	t.Helper()

	require.Equal(t, len(expected), len(actual))

	slices.SortFunc(expected, upgradeComparator)
	slices.SortFunc(actual, upgradeComparator)
	for i := range expected {
		require.EqualValues(t, expected[i].From, actual[i].From)
		require.EqualValues(t, expected[i].To, actual[i].To)
		equalVulnerabilityInPackages(t, expected[i].Fixes, actual[i].Fixes)
	}
}

func equalVulnerabilityInPackages(t *testing.T, expected, actual []*remediation.VulnerabilityInPackage) {
	t.Helper()

	require.Equal(t, len(expected), len(actual))
	slices.SortFunc(expected, vulnInPackageComparator)
	slices.SortFunc(actual, vulnInPackageComparator)
	for j := range expected {
		require.EqualValues(t, expected[j], actual[j])
	}
}

func vulnInPackageComparator(a, b *remediation.VulnerabilityInPackage) int {
	return strings.Compare(
		a.VulnerablePackage.Name+a.VulnerablePackage.Version+string(a.Vulnerability.ID),
		b.VulnerablePackage.Name+b.VulnerablePackage.Version+string(b.Vulnerability.ID))
}

func upgradeComparator(a, b *remediation.Upgrade) int {
	return strings.Compare(a.To.Name+a.To.Version, b.To.Name+b.To.Version)
}

// Utils.
func newPackage(p string) remediation.Package {
	name, version := legacyUtils.SplitNameAndVersion(p)
	return remediation.Package{name, version}
}

func newDependencyPath(p ...string) remediation.DependencyPath {
	var output remediation.DependencyPath
	for _, s := range p {
		output = append(output, newPackage(s))
	}
	return output
}
