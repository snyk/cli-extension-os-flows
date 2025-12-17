package presenters_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/muesli/termenv"
	"github.com/snyk/error-catalog-golang-public/snyk"
	"github.com/snyk/go-application-framework/pkg/networking"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/cli-extension-os-flows/internal/presenters"
)

func Test_RenderError(t *testing.T) {
	defaultContext := context.Background()
	contextWithInteractionID := context.WithValue(defaultContext, networking.InteractionIdKey, "urn:snyk:interaction:some-UUID")

	for _, severity := range []string{"warn", "error", "fatal"} {
		t.Run(
			fmt.Sprintf("colors for severity %s", severity), func(t *testing.T) {
				err := snyk.NewTooManyRequestsError("")
				err.Level = severity
				lipgloss.SetColorProfile(termenv.TrueColor)
				output := presenters.RenderError(defaultContext, &err)
				snaps.MatchSnapshot(t, output)

				lipgloss.SetColorProfile(termenv.TrueColor)
				lipgloss.SetHasDarkBackground(true)
				outputDark := presenters.RenderError(defaultContext, &err)
				snaps.MatchSnapshot(t, outputDark)
			})
	}

	t.Run("without status code", func(t *testing.T) {
		lipgloss.SetColorProfile(termenv.TrueColor)
		lipgloss.SetHasDarkBackground(false)
		err := snyk.NewBadRequestError("A short error description")
		// no error code => no error catalog link
		err.StatusCode = 0
		output := presenters.RenderError(defaultContext, &err)

		assert.NotContains(t, output, "Status:")
		snaps.MatchSnapshot(t, output)
	})

	t.Run("without links", func(t *testing.T) {
		lipgloss.SetColorProfile(termenv.TrueColor)
		lipgloss.SetHasDarkBackground(false)
		err := snyk.NewBadRequestError("A short error description")
		// no error code => no error catalog link
		err.ErrorCode = ""
		output := presenters.RenderError(defaultContext, &err)

		assert.NotContains(t, output, "Help:")
		snaps.MatchSnapshot(t, output)
	})

	t.Run("with links", func(t *testing.T) {
		lipgloss.SetColorProfile(termenv.TrueColor)
		lipgloss.SetHasDarkBackground(false)
		err := snyk.NewServerError("An error")
		err.Links = append(err.Links, "https://docs.snyk.io/getting-started/supported-languages-frameworks-and-feature-availability-overview#code-analysis-snyk-code")
		output := presenters.RenderError(defaultContext, &err)

		assert.Contains(t, output, "Docs:")
		snaps.MatchSnapshot(t, output)
	})

	t.Run("with context", func(t *testing.T) {
		lipgloss.SetColorProfile(termenv.TrueColor)
		lipgloss.SetHasDarkBackground(false)
		err := snyk.NewServerError("An error")
		err.Links = append(err.Links, "https://docs.snyk.io/getting-started/supported-languages-frameworks-and-feature-availability-overview#code-analysis-snyk-code")
		output := presenters.RenderError(contextWithInteractionID, &err)

		assert.Contains(t, output, "Docs:")
		assert.Contains(t, output, "ID:")
		snaps.MatchSnapshot(t, output)
	})
}

func Test_RenderEarlyAccessBanner(t *testing.T) {
	testDocsURL := "https://docs.snyk.io/test"

	t.Run("renders banner with expected content in light mode", func(t *testing.T) {
		lipgloss.SetColorProfile(termenv.TrueColor)
		lipgloss.SetHasDarkBackground(false)

		output := presenters.RenderEarlyAccessBanner(testDocsURL)

		assert.Contains(t, output, "EARLY ACCESS")
		assert.Contains(t, output, "This command is in Early Access")
		assert.Contains(t, output, "Performance, stability,")
		assert.Contains(t, output, "and behavior are subject to change.")
		assert.Contains(t, output, "Your feedback helps us improve!")
		assert.Contains(t, output, testDocsURL)
		snaps.MatchSnapshot(t, output)
	})

	t.Run("renders banner with expected content in dark mode", func(t *testing.T) {
		lipgloss.SetColorProfile(termenv.TrueColor)
		lipgloss.SetHasDarkBackground(true)

		output := presenters.RenderEarlyAccessBanner(testDocsURL)

		assert.Contains(t, output, "EARLY ACCESS")
		assert.Contains(t, output, "This command is in Early Access")
		assert.Contains(t, output, testDocsURL)
		snaps.MatchSnapshot(t, output)
	})

	t.Run("uses default SBOM docs URL constant", func(t *testing.T) {
		lipgloss.SetColorProfile(termenv.TrueColor)

		output := presenters.RenderEarlyAccessBanner(presenters.SBOMEarlyAccessDocsURL)

		assert.Contains(t, output, presenters.SBOMEarlyAccessDocsURL)
	})
}
