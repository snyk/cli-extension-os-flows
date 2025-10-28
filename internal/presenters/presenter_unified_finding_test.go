package presenters_test

import (
	"bytes"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/google/uuid"
	"github.com/muesli/termenv"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/presenters"
	"github.com/snyk/cli-extension-os-flows/internal/util"
)

func TestJsonWriter(t *testing.T) {
	t.Run("strip whitespaces while writing", func(t *testing.T) {
		buffer := &bytes.Buffer{}
		writerUnderTest := presenters.NewJSONWriter(buffer, true)

		input := []byte(`{
	"name": "myName",
	"address": "myAddr"
}`)

		expected := `{"name": "myName","address": "myAddr"}`

		bytesWritten, err := writerUnderTest.Write(input)
		assert.NoError(t, err)
		assert.Equal(t, len(input), bytesWritten)
		assert.Equal(t, expected, buffer.String())
	})

	t.Run("don't strip whitespaces while writing", func(t *testing.T) {
		buffer := &bytes.Buffer{}
		writerUnderTest := presenters.NewJSONWriter(buffer, false)

		input := []byte(`{
	"name": "myName",
    "address": "myAddr"
}`)

		bytesWritten, err := writerUnderTest.Write(input)
		assert.NoError(t, err)
		assert.Equal(t, len(input), bytesWritten)
		assert.Equal(t, input, buffer.Bytes())
	})
}

func TestUnifiedFindingPresenter_CliOutput(t *testing.T) {
	t.Run("license finding should not have risk score", func(t *testing.T) {
		// setup
		config := configuration.New()
		buffer := &bytes.Buffer{}

		problemID := uuid.New().String()

		loc := testapi.FindingLocation{}
		loc.FromPackageLocation(testapi.PackageLocation{
			Package: testapi.Package{
				Name:    "foo",
				Version: "1.0.0",
			},
			Type: testapi.PackageLocationTypePackage,
		})

		depPathEv := testapi.Evidence{}
		depPathEv.FromDependencyPathEvidence(testapi.DependencyPathEvidence{
			Path: []testapi.Package{
				{
					Name:    "root",
					Version: "0.0.0",
				},
				{
					Name:    "foo",
					Version: "1.0.0",
				},
			},
			Source: testapi.DependencyPath,
		})

		licenseFinding := testapi.FindingData{
			Id:   util.Ptr(uuid.New()),
			Type: util.Ptr(testapi.Findings),
			Attributes: &testapi.FindingAttributes{
				Title: "GPL-3.0-only",
				Rating: testapi.Rating{
					Severity: testapi.Severity("medium"),
				},
				Evidence:  []testapi.Evidence{depPathEv},
				Locations: []testapi.FindingLocation{loc},
				Problems: func() []testapi.Problem {
					var p testapi.Problem
					err := p.FromSnykLicenseProblem(testapi.SnykLicenseProblem{
						Id:      problemID,
						License: "license",
					})
					assert.NoError(t, err)
					return []testapi.Problem{p}
				}(),
			},
		}

		projectResult := &presenters.UnifiedProjectResult{
			Findings: []testapi.FindingData{licenseFinding},
			Summary: &json_schemas.TestSummary{
				Type:             "open-source",
				Path:             "test/path",
				SeverityOrderAsc: []string{"low", "medium", "high", "critical"},
				Results: []json_schemas.TestSummaryResult{
					{
						Severity: "medium",
						Open:     1,
					},
				},
			},
		}

		presenter := presenters.NewUnifiedFindingsRenderer(
			[]*presenters.UnifiedProjectResult{projectResult},
			config,
			buffer,
		)

		// execute
		err := presenter.RenderTemplate(presenters.DefaultTemplateFiles, presenters.DefaultMimeType)

		// assert
		assert.NoError(t, err)
		output := buffer.String()
		assert.NotContains(t, output, "Risk Score:")
	})

	t.Run("vulnerability finding should have risk score", func(t *testing.T) {
		// setup
		config := configuration.New()
		buffer := &bytes.Buffer{}

		riskScore := uint16(780)
		vulnFinding := testapi.FindingData{
			Id:   util.Ptr(uuid.New()),
			Type: util.Ptr(testapi.Findings),
			Attributes: &testapi.FindingAttributes{
				Title: "High severity vulnerability",
				Risk: testapi.Risk{
					RiskScore: &testapi.RiskScore{
						Value: riskScore,
					},
				},
				Rating: testapi.Rating{
					Severity: testapi.Severity("high"),
				},
			},
		}

		projectResult := &presenters.UnifiedProjectResult{
			Findings: []testapi.FindingData{vulnFinding},
			Summary: &json_schemas.TestSummary{
				Type:             "open-source",
				Path:             "test/path",
				SeverityOrderAsc: []string{"low", "medium", "high", "critical"},
				Results: []json_schemas.TestSummaryResult{
					{
						Severity: "high",
						Open:     1,
					},
				},
			},
		}

		presenter := presenters.NewUnifiedFindingsRenderer(
			[]*presenters.UnifiedProjectResult{projectResult},
			config,
			buffer,
		)

		// execute
		err := presenter.RenderTemplate(presenters.DefaultTemplateFiles, presenters.DefaultMimeType)

		// assert
		assert.NoError(t, err)
		output := buffer.String()
		assert.Contains(t, output, "Risk Score: 780")
	})

	t.Run("snapshot test of human-readable output", func(t *testing.T) {
		// setup
		config := configuration.New()
		buffer := &bytes.Buffer{}
		lipgloss.SetColorProfile(termenv.Ascii)

		loc := testapi.FindingLocation{}
		loc.FromPackageLocation(testapi.PackageLocation{
			Package: testapi.Package{
				Name:    "foo",
				Version: "1.0.0",
			},
			Type: testapi.PackageLocationTypePackage,
		})

		depPathEv := testapi.Evidence{}
		depPathEv.FromDependencyPathEvidence(testapi.DependencyPathEvidence{
			Path: []testapi.Package{
				{
					Name:    "root",
					Version: "0.0.0",
				},
				{
					Name:    "foo",
					Version: "1.0.0",
				},
			},
			Source: testapi.DependencyPath,
		})

		riskScore := uint16(780)
		problemID := "SNYK-JS-VM2-5537100"
		vulnFinding := testapi.FindingData{
			Id:   util.Ptr(uuid.MustParse("22222222-2222-2222-2222-222222222222")),
			Type: util.Ptr(testapi.Findings),
			Attributes: &testapi.FindingAttributes{
				Title: "High severity vulnerability",
				Risk: testapi.Risk{
					RiskScore: &testapi.RiskScore{
						Value: riskScore,
					},
				},
				Rating: testapi.Rating{
					Severity: testapi.Severity("high"),
				},
				Evidence:  []testapi.Evidence{depPathEv},
				Locations: []testapi.FindingLocation{loc},
				Problems: func() []testapi.Problem {
					var p testapi.Problem
					err := p.FromSnykVulnProblem(testapi.SnykVulnProblem{
						Id:     problemID,
						Source: testapi.SnykVuln,
					})
					assert.NoError(t, err)
					return []testapi.Problem{p}
				}(),
			},
		}

		licProblemID := "snyk:lic:npm:web3-core:LGPL-3.0"
		licenseFinding := testapi.FindingData{
			Id:   util.Ptr(uuid.MustParse("33333333-3333-3333-3333-333333333333")),
			Type: util.Ptr(testapi.Findings),
			Attributes: &testapi.FindingAttributes{
				Title: "LGPL-3.0 license",
				Rating: testapi.Rating{
					Severity: testapi.Severity("medium"),
				},
				Evidence:  []testapi.Evidence{depPathEv},
				Locations: []testapi.FindingLocation{loc},
				Problems: func() []testapi.Problem {
					var p testapi.Problem
					err := p.FromSnykLicenseProblem(testapi.SnykLicenseProblem{
						Id:      licProblemID,
						License: "LGPL-3.0",
						Instructions: []testapi.SnykvulndbLicenseInstructions{
							{
								License: "LGPL-3.0",
								Content: "This license requires source code disclosure when modified.",
							},
						},
					})
					assert.NoError(t, err)
					return []testapi.Problem{p}
				}(),
			},
		}

		projectResult := &presenters.UnifiedProjectResult{
			Findings: []testapi.FindingData{vulnFinding, licenseFinding},
			Summary: &json_schemas.TestSummary{
				Type:             "open-source",
				Path:             "test/path",
				SeverityOrderAsc: []string{"low", "medium", "high", "critical"},
				Results: []json_schemas.TestSummaryResult{
					{
						Severity: "high",
						Open:     1,
						Total:    1,
					},
					{
						Severity: "medium",
						Open:     1,
						Total:    1,
					},
				},
			},
		}

		presenter := presenters.NewUnifiedFindingsRenderer(
			[]*presenters.UnifiedProjectResult{projectResult},
			config,
			buffer,
		)

		// execute
		err := presenter.RenderTemplate(presenters.DefaultTemplateFiles, presenters.DefaultMimeType)

		// assert
		assert.NoError(t, err)
		snaps.MatchSnapshot(t, buffer.String())
	})

	t.Run("snapshot test with multiple license instructions", func(t *testing.T) {
		config := configuration.New()
		buffer := &bytes.Buffer{}
		lipgloss.SetColorProfile(termenv.Ascii)

		loc := testapi.FindingLocation{}
		loc.FromPackageLocation(testapi.PackageLocation{
			Package: testapi.Package{
				Name:    "foo",
				Version: "1.0.0",
			},
			Type: testapi.PackageLocationTypePackage,
		})

		depPathEv := testapi.Evidence{}
		depPathEv.FromDependencyPathEvidence(testapi.DependencyPathEvidence{
			Path: []testapi.Package{
				{
					Name:    "root",
					Version: "0.0.0",
				},
				{
					Name:    "foo",
					Version: "1.0.0",
				},
			},
			Source: testapi.DependencyPath,
		})

		// Create a dual-licensed package with instructions for each license
		dualLicenseFinding := testapi.FindingData{
			Id:   util.Ptr(uuid.MustParse("44444444-4444-4444-4444-444444444444")),
			Type: util.Ptr(testapi.Findings),
			Attributes: &testapi.FindingAttributes{
				Title: "GPL-3.0 OR MIT license",
				Rating: testapi.Rating{
					Severity: testapi.Severity("high"),
				},
				Evidence:  []testapi.Evidence{depPathEv},
				Locations: []testapi.FindingLocation{loc},
				Problems: func() []testapi.Problem {
					var p testapi.Problem
					err := p.FromSnykLicenseProblem(testapi.SnykLicenseProblem{
						Id:      "snyk:lic:npm:dual-pkg:GPL-3.0-OR-MIT",
						License: "GPL-3.0 OR MIT",
						Instructions: []testapi.SnykvulndbLicenseInstructions{
							{
								License: "GPL-3.0",
								Content: "Strong copyleft license. Requires source code disclosure for modifications.",
							},
							{
								License: "MIT",
								Content: "Permissive license. Must include original copyright notice.",
							},
						},
					})
					assert.NoError(t, err)
					return []testapi.Problem{p}
				}(),
			},
		}

		projectResult := &presenters.UnifiedProjectResult{
			Findings: []testapi.FindingData{dualLicenseFinding},
			Summary: &json_schemas.TestSummary{
				Type:             "open-source",
				Path:             "test/path",
				SeverityOrderAsc: []string{"low", "medium", "high", "critical"},
				Results: []json_schemas.TestSummaryResult{
					{
						Severity: "high",
						Open:     1,
						Total:    1,
					},
				},
			},
		}

		presenter := presenters.NewUnifiedFindingsRenderer(
			[]*presenters.UnifiedProjectResult{projectResult},
			config,
			buffer,
		)

		err := presenter.RenderTemplate(presenters.DefaultTemplateFiles, presenters.DefaultMimeType)
		assert.NoError(t, err)
		snaps.MatchSnapshot(t, buffer.String())
	})

	t.Run("snapshot test with license without instructions", func(t *testing.T) {
		config := configuration.New()
		buffer := &bytes.Buffer{}
		lipgloss.SetColorProfile(termenv.Ascii)

		loc := testapi.FindingLocation{}
		loc.FromPackageLocation(testapi.PackageLocation{
			Package: testapi.Package{
				Name:    "foo",
				Version: "1.0.0",
			},
			Type: testapi.PackageLocationTypePackage,
		})

		depPathEv := testapi.Evidence{}
		depPathEv.FromDependencyPathEvidence(testapi.DependencyPathEvidence{
			Path: []testapi.Package{
				{
					Name:    "root",
					Version: "0.0.0",
				},
				{
					Name:    "foo",
					Version: "1.0.0",
				},
			},
			Source: testapi.DependencyPath,
		})

		// Create a license finding without instructions
		licenseFinding := testapi.FindingData{
			Id:   util.Ptr(uuid.MustParse("55555555-5555-5555-5555-555555555555")),
			Type: util.Ptr(testapi.Findings),
			Attributes: &testapi.FindingAttributes{
				Title: "Apache-2.0 license",
				Rating: testapi.Rating{
					Severity: testapi.Severity("medium"),
				},
				Evidence:  []testapi.Evidence{depPathEv},
				Locations: []testapi.FindingLocation{loc},
				Problems: func() []testapi.Problem {
					var p testapi.Problem
					err := p.FromSnykLicenseProblem(testapi.SnykLicenseProblem{
						Id:           "snyk:lic:npm:test-pkg:Apache-2.0",
						License:      "Apache-2.0",
						Instructions: []testapi.SnykvulndbLicenseInstructions{}, // No instructions
					})
					assert.NoError(t, err)
					return []testapi.Problem{p}
				}(),
			},
		}

		projectResult := &presenters.UnifiedProjectResult{
			Findings: []testapi.FindingData{licenseFinding},
			Summary: &json_schemas.TestSummary{
				Type:             "open-source",
				Path:             "test/path",
				SeverityOrderAsc: []string{"low", "medium", "high", "critical"},
				Results: []json_schemas.TestSummaryResult{
					{
						Severity: "medium",
						Open:     1,
						Total:    1,
					},
				},
			},
		}

		presenter := presenters.NewUnifiedFindingsRenderer(
			[]*presenters.UnifiedProjectResult{projectResult},
			config,
			buffer,
		)

		err := presenter.RenderTemplate(presenters.DefaultTemplateFiles, presenters.DefaultMimeType)
		assert.NoError(t, err)
		snaps.MatchSnapshot(t, buffer.String())
	})

	// summary shows security only when there are vulnerability findings and no license findings
	t.Run("summary shows only security when no license issues", func(t *testing.T) {
		config := configuration.New()
		buffer := &bytes.Buffer{}

		vulnFinding := testapi.FindingData{
			Id:   util.Ptr(uuid.New()),
			Type: util.Ptr(testapi.Findings),
			Attributes: &testapi.FindingAttributes{
				Title:  "High severity vulnerability",
				Rating: testapi.Rating{Severity: testapi.Severity("high")},
			},
		}

		projectResult := &presenters.UnifiedProjectResult{
			Findings: []testapi.FindingData{vulnFinding},
			Summary: &json_schemas.TestSummary{
				Type:             "open-source",
				Path:             "test/path",
				SeverityOrderAsc: []string{"low", "medium", "high", "critical"},
				Results:          []json_schemas.TestSummaryResult{{Severity: "high", Open: 1, Total: 1}},
			},
		}

		presenter := presenters.NewUnifiedFindingsRenderer(
			[]*presenters.UnifiedProjectResult{projectResult},
			config,
			buffer,
		)

		err := presenter.RenderTemplate(presenters.DefaultTemplateFiles, presenters.DefaultMimeType)
		assert.NoError(t, err)

		out := buffer.String()
		assert.Contains(t, out, "Total security issues: 1")
		assert.NotContains(t, out, "Total license issues")
	})

	// summary shows license only when there are license findings and no vulnerability findings
	t.Run("summary shows only license when no security issues", func(t *testing.T) {
		config := configuration.New()
		buffer := &bytes.Buffer{}

		loc := testapi.FindingLocation{}
		err := loc.FromPackageLocation(testapi.PackageLocation{
			Package: testapi.Package{
				Name:    "foo",
				Version: "1.0.0",
			},
			Type: testapi.PackageLocationTypePackage,
		})
		require.NoError(t, err)

		ev := testapi.Evidence{}
		err = ev.FromDependencyPathEvidence(testapi.DependencyPathEvidence{
			Path: []testapi.Package{
				{
					Name:    "root",
					Version: "0.0.0",
				},
				{
					Name:    "foo",
					Version: "1.0.0",
				},
			},
			Source: testapi.DependencyPath,
		})
		require.NoError(t, err)

		problemID := uuid.New().String()
		licenseFinding := testapi.FindingData{
			Id:   util.Ptr(uuid.New()),
			Type: util.Ptr(testapi.Findings),
			Attributes: &testapi.FindingAttributes{
				Title:     "LGPL-3.0 license",
				Rating:    testapi.Rating{Severity: testapi.Severity("medium")},
				Locations: []testapi.FindingLocation{loc},
				Evidence:  []testapi.Evidence{ev},
				Problems: func() []testapi.Problem {
					var p testapi.Problem
					err = p.FromSnykLicenseProblem(testapi.SnykLicenseProblem{Id: problemID, License: string(testapi.SnykLicense)})
					assert.NoError(t, err)
					return []testapi.Problem{p}
				}(),
			},
		}

		projectResult := &presenters.UnifiedProjectResult{
			Findings: []testapi.FindingData{licenseFinding},
			Summary: &json_schemas.TestSummary{
				Type:             "open-source",
				Path:             "test/path",
				SeverityOrderAsc: []string{"low", "medium", "high", "critical"},
				Results:          []json_schemas.TestSummaryResult{{Severity: "medium", Open: 1, Total: 1}},
			},
		}

		presenter := presenters.NewUnifiedFindingsRenderer(
			[]*presenters.UnifiedProjectResult{projectResult},
			config,
			buffer,
		)

		err = presenter.RenderTemplate(presenters.DefaultTemplateFiles, presenters.DefaultMimeType)
		assert.NoError(t, err)

		out := buffer.String()
		assert.Contains(t, out, "Total license issues: 1")
		assert.NotContains(t, out, "Total security issues")
	})

	// summary shows Total issues: 0 when no findings of any kind are present
	t.Run("summary shows Total issues: 0 when no issues", func(t *testing.T) {
		config := configuration.New()
		buffer := &bytes.Buffer{}

		projectResult := &presenters.UnifiedProjectResult{
			Findings: []testapi.FindingData{},
			Summary: &json_schemas.TestSummary{
				Type:             "open-source",
				Path:             "test/path",
				SeverityOrderAsc: []string{"low", "medium", "high", "critical"},
				Results:          []json_schemas.TestSummaryResult{},
			},
		}

		presenter := presenters.NewUnifiedFindingsRenderer(
			[]*presenters.UnifiedProjectResult{projectResult},
			config,
			buffer,
		)

		err := presenter.RenderTemplate(presenters.DefaultTemplateFiles, presenters.DefaultMimeType)
		assert.NoError(t, err)

		out := buffer.String()
		assert.Contains(t, out, "Total issues: 0")
		assert.NotContains(t, out, "Total security issues")
		assert.NotContains(t, out, "Total license issues")
	})
}

// TestUnifiedFindingPresenter_PendingIgnore_ShownAsOpenWithLabelAndBang verifies that pending ignores are shown as open with a label and ! marker.
func TestUnifiedFindingPresenter_PendingIgnore_ShownAsOpenWithLabelAndBang(t *testing.T) {
	config := configuration.New()
	buffer := &bytes.Buffer{}
	// Use ASCII to avoid color codes in assertions
	lipgloss.SetColorProfile(termenv.Ascii)

	pendingFinding := testapi.FindingData{
		Id:   util.Ptr(uuid.New()),
		Type: util.Ptr(testapi.Findings),
		Attributes: &testapi.FindingAttributes{
			Title:       "Pending Suppression Finding",
			Rating:      testapi.Rating{Severity: testapi.Severity("low")},
			Suppression: &testapi.Suppression{Status: testapi.SuppressionStatusPendingIgnoreApproval},
		},
	}

	projectResult := &presenters.UnifiedProjectResult{
		Findings: []testapi.FindingData{pendingFinding},
		Summary: &json_schemas.TestSummary{
			Type:             "open-source",
			Path:             "test/path",
			SeverityOrderAsc: []string{"low", "medium", "high", "critical"},
			Results:          []json_schemas.TestSummaryResult{{Severity: "low", Open: 1, Total: 1}},
		},
	}

	presenter := presenters.NewUnifiedFindingsRenderer([]*presenters.UnifiedProjectResult{projectResult}, config, buffer)
	err := presenter.RenderTemplate(presenters.DefaultTemplateFiles, presenters.DefaultMimeType)
	assert.NoError(t, err)

	out := buffer.String()
	// Label should be inline on the issue line (after the title) with a preceding space
	assert.Contains(t, out, " ! [LOW] Pending Suppression Finding [ PENDING IGNORE... ]")
}

// TestUnifiedFindingPresenter_Ignored_ShownInIgnoredSectionWithBang verifies that ignored findings are shown in the ignored section with a ! marker.
func TestUnifiedFindingPresenter_Ignored_ShownInIgnoredSectionWithBang(t *testing.T) {
	config := configuration.New()
	buffer := &bytes.Buffer{}
	// Ensure ignored section is rendered
	config.Set("include-ignores", true)
	// Use ASCII to avoid color codes in assertions
	lipgloss.SetColorProfile(termenv.Ascii)

	ignoredFinding := testapi.FindingData{
		Id:   util.Ptr(uuid.New()),
		Type: util.Ptr(testapi.Findings),
		Attributes: &testapi.FindingAttributes{
			Title:       "Ignored Suppression Finding",
			Rating:      testapi.Rating{Severity: testapi.Severity("medium")},
			Suppression: &testapi.Suppression{Status: testapi.SuppressionStatusIgnored},
		},
	}

	projectResult := &presenters.UnifiedProjectResult{
		Findings: []testapi.FindingData{ignoredFinding},
		Summary: &json_schemas.TestSummary{
			Type:             "open-source",
			Path:             "test/path",
			SeverityOrderAsc: []string{"low", "medium", "high", "critical"},
			Results:          []json_schemas.TestSummaryResult{{Severity: "medium", Ignored: 1, Total: 1}},
		},
	}

	presenter := presenters.NewUnifiedFindingsRenderer([]*presenters.UnifiedProjectResult{projectResult}, config, buffer)
	err := presenter.RenderTemplate(presenters.DefaultTemplateFiles, presenters.DefaultMimeType)
	assert.NoError(t, err)

	out := buffer.String()
	assert.Contains(t, out, "Ignored Issues")
	// Ignored entries appear with ! and IGNORED label
	assert.Contains(t, out, " ! [IGNORED] [MEDIUM] Ignored Suppression Finding")
}

func TestUnifiedFindingPresenter_IgnoredFindingsNotCountedInSummary(t *testing.T) {
	config := configuration.New()
	buffer := &bytes.Buffer{}

	depPathEv := testapi.Evidence{}
	err := depPathEv.FromDependencyPathEvidence(testapi.DependencyPathEvidence{
		Path: []testapi.Package{
			{Name: "root", Version: "1.0.0"},
			{Name: "vulnerable-pkg", Version: "1.0.0"},
		},
		Source: testapi.DependencyPath,
	})
	require.NoError(t, err)

	// One open finding with 1 vulnerable path
	openFinding := testapi.FindingData{
		Id:   util.Ptr(uuid.New()),
		Type: util.Ptr(testapi.Findings),
		Attributes: &testapi.FindingAttributes{
			Title:    "Open Vulnerability",
			Rating:   testapi.Rating{Severity: testapi.Severity("high")},
			Evidence: []testapi.Evidence{depPathEv},
		},
	}

	// One ignored finding with 1 vulnerable path (should not be counted)
	ignoredFinding := testapi.FindingData{
		Id:   util.Ptr(uuid.New()),
		Type: util.Ptr(testapi.Findings),
		Attributes: &testapi.FindingAttributes{
			Title:       "Ignored Vulnerability",
			Rating:      testapi.Rating{Severity: testapi.Severity("critical")},
			Suppression: &testapi.Suppression{Status: testapi.SuppressionStatusIgnored},
			Evidence:    []testapi.Evidence{depPathEv},
		},
	}

	projectResult := &presenters.UnifiedProjectResult{
		Findings:             []testapi.FindingData{openFinding, ignoredFinding},
		DependencyCount:      1,
		VulnerablePathsCount: 1, // Only count paths from open findings
		Summary: &json_schemas.TestSummary{
			Type:             "open-source",
			SeverityOrderAsc: []string{"low", "medium", "high", "critical"},
			Results: []json_schemas.TestSummaryResult{
				{Severity: "high", Open: 1, Total: 1},
				{Severity: "critical", Ignored: 1, Total: 1},
			},
		},
	}

	presenter := presenters.NewUnifiedFindingsRenderer([]*presenters.UnifiedProjectResult{projectResult}, config, buffer)
	err = presenter.RenderTemplate(presenters.DefaultTemplateFiles, presenters.DefaultMimeType)
	assert.NoError(t, err)

	out := buffer.String()

	assert.Contains(t, out, "found 1 issue")
	assert.Contains(t, out, "1 vulnerable path")
}

// verifies that license instructions appear in output.
func TestUnifiedFindingPresenter_LicenseInstructions(t *testing.T) {
	config := configuration.New()
	buffer := &bytes.Buffer{}
	lipgloss.SetColorProfile(termenv.Ascii)

	licProblem := testapi.SnykLicenseProblem{
		Id:      "snyk:lic:npm:web3-core:LGPL-3.0",
		License: "LGPL-3.0",
		Instructions: []testapi.SnykvulndbLicenseInstructions{
			{
				License: "LGPL-3.0",
				Content: "This license requires you to disclose source code changes.",
			},
		},
	}

	var p testapi.Problem
	err := p.FromSnykLicenseProblem(licProblem)
	assert.NoError(t, err)

	loc := testapi.FindingLocation{}
	err = loc.FromPackageLocation(testapi.PackageLocation{
		Package: testapi.Package{
			Name:    "foo",
			Version: "1.0.0",
		},
		Type: testapi.PackageLocationTypePackage,
	})
	require.NoError(t, err)

	ev := testapi.Evidence{}
	err = ev.FromDependencyPathEvidence(testapi.DependencyPathEvidence{
		Path: []testapi.Package{
			{
				Name:    "root",
				Version: "0.0.0",
			},
			{
				Name:    "foo",
				Version: "1.0.0",
			},
		},
		Source: testapi.DependencyPath,
	})
	require.NoError(t, err)

	licenseFinding := testapi.FindingData{
		Id:   util.Ptr(uuid.New()),
		Type: util.Ptr(testapi.Findings),
		Attributes: &testapi.FindingAttributes{
			Title:     "LGPL-3.0 license",
			Locations: []testapi.FindingLocation{loc},
			Evidence:  []testapi.Evidence{ev},
			Rating:    testapi.Rating{Severity: testapi.Severity("medium")},
			Problems:  []testapi.Problem{p},
		},
	}

	projectResult := &presenters.UnifiedProjectResult{
		Findings: []testapi.FindingData{licenseFinding},
		Summary: &json_schemas.TestSummary{
			Type:             "open-source",
			Path:             "test/path",
			SeverityOrderAsc: []string{"low", "medium", "high", "critical"},
			Results:          []json_schemas.TestSummaryResult{{Severity: "medium", Open: 1, Total: 1}},
		},
	}

	presenter := presenters.NewUnifiedFindingsRenderer([]*presenters.UnifiedProjectResult{projectResult}, config, buffer)
	err = presenter.RenderTemplate(presenters.DefaultTemplateFiles, presenters.DefaultMimeType)
	assert.NoError(t, err)

	out := buffer.String()
	assert.Contains(t, out, "Legal instructions:")
	assert.Contains(t, out, "○ for LGPL-3.0: This license requires you to disclose source code changes.")
}

// verifies that license findings without instructions don't show the instructions field.
func TestUnifiedFindingPresenter_LicenseWithoutInstructions(t *testing.T) {
	config := configuration.New()
	buffer := &bytes.Buffer{}
	lipgloss.SetColorProfile(termenv.Ascii)

	loc := testapi.FindingLocation{}
	err := loc.FromPackageLocation(testapi.PackageLocation{
		Package: testapi.Package{
			Name:    "foo",
			Version: "1.0.0",
		},
		Type: testapi.PackageLocationTypePackage,
	})
	require.NoError(t, err)

	ev := testapi.Evidence{}
	err = ev.FromDependencyPathEvidence(testapi.DependencyPathEvidence{
		Path: []testapi.Package{
			{
				Name:    "root",
				Version: "0.0.0",
			},
			{
				Name:    "foo",
				Version: "1.0.0",
			},
		},
		Source: testapi.DependencyPath,
	})
	require.NoError(t, err)

	licenseFinding := testapi.FindingData{
		Id:   util.Ptr(uuid.New()),
		Type: util.Ptr(testapi.Findings),
		Attributes: &testapi.FindingAttributes{
			Title: "MIT license",
			Rating: testapi.Rating{
				Severity: testapi.Severity("low"),
			},
			Evidence:  []testapi.Evidence{ev},
			Locations: []testapi.FindingLocation{loc},
			Problems: func() []testapi.Problem {
				var p testapi.Problem
				err = p.FromSnykLicenseProblem(testapi.SnykLicenseProblem{
					Id:           "snyk:lic:npm:test-pkg:MIT",
					License:      "MIT",
					Instructions: []testapi.SnykvulndbLicenseInstructions{},
				})
				assert.NoError(t, err)
				return []testapi.Problem{p}
			}(),
		},
	}

	projectResult := &presenters.UnifiedProjectResult{
		Findings: []testapi.FindingData{licenseFinding},
		Summary: &json_schemas.TestSummary{
			Type:             "open-source",
			Path:             "test/path",
			SeverityOrderAsc: []string{"low", "medium", "high", "critical"},
			Results:          []json_schemas.TestSummaryResult{{Severity: "low", Open: 1, Total: 1}},
		},
	}

	presenter := presenters.NewUnifiedFindingsRenderer([]*presenters.UnifiedProjectResult{projectResult}, config, buffer)
	err = presenter.RenderTemplate(presenters.DefaultTemplateFiles, presenters.DefaultMimeType)
	assert.NoError(t, err)

	out := buffer.String()
	assert.NotContains(t, out, "Legal instructions:")
	assert.Contains(t, out, "MIT license")
}
