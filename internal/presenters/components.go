package presenters

import (
	"context"
	"fmt"

	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/snyk/go-application-framework/pkg/networking"

	"github.com/charmbracelet/lipgloss"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
)

const (
	SNYK_DOCS_URL                = "https://docs.snyk.io"
	SNYK_DOCS_ERROR_CATALOG_PATH = "/scan-with-snyk/error-catalog"
)

const valueStyleWidth = 80

func errorLevelToStyle(errLevel string) lipgloss.Style {
	style := lipgloss.NewStyle().
		PaddingLeft(1).
		PaddingRight(1).
		Background(lipgloss.Color("1")).
		Foreground(lipgloss.Color("15"))

	if errLevel == "warn" {
		style.
			Background(lipgloss.Color("3")).
			Foreground(lipgloss.Color("0"))
	}

	return style
}

func RenderError(err snyk_errors.Error, ctx context.Context) string {
	var body []string

	level := strings.ToUpper(err.Level)
	backgroundHighlight := errorLevelToStyle(err.Level)
	label := lipgloss.NewStyle().Width(8)
	value := lipgloss.NewStyle().PaddingLeft(1).PaddingRight(1)

	if len(err.Description) > 0 {
		desc := err.Description
		re := regexp.MustCompile("\n+")
		lines := re.Split(desc, -1)

		if len(lines) > 1 {
			lines = lines[0:2]
			for i, l := range lines {
				lines[i] = strings.Trim(l, " \n")
			}
			desc = strings.Join(lines, " ")
		}

		body = append(body, lipgloss.JoinHorizontal(lipgloss.Top,
			label.Render(""),
			value.Copy().Width(valueStyleWidth).Render(desc),
		))
	}

	if len(err.Detail) > 0 {
		detailValue := lipgloss.NewStyle().PaddingLeft(3).PaddingRight(1)
		body = append(body, lipgloss.JoinHorizontal(lipgloss.Top,
			label.Render("\n"),
			detailValue.Copy().Width(valueStyleWidth).Render("\n"+err.Detail),
		))
	}

	if len(err.Detail) > 0 || len(err.Description) > 0 {
		body = append(body, "")
	}

	title := strings.TrimSpace(err.Title)
	if len(err.ErrorCode) > 0 {
		fragment := "#" + strings.ToLower(err.ErrorCode)
		link := SNYK_DOCS_URL + SNYK_DOCS_ERROR_CATALOG_PATH + fragment
		err.Links = append([]string{link}, err.Links...)
		title = title + fmt.Sprintf(" (%s)", err.ErrorCode)
	}

	if err.StatusCode > http.StatusOK {
		body = append(body, lipgloss.JoinHorizontal(lipgloss.Top,
			label.Render("Status:"),
			value.Render(strconv.Itoa(err.StatusCode)+" "+http.StatusText(err.StatusCode)),
		))
	}

	if len(err.Links) > 0 {
		link := err.Links[0] + "\n"
		body = append(body, lipgloss.JoinHorizontal(lipgloss.Top,
			label.Render("Docs:"),
			value.Render(link),
		))
	}

	if v := ctx.Value(networking.InteractionIdKey); v != nil {
		interactionId, ok := v.(string)
		if ok {
			body = append(body, lipgloss.JoinHorizontal(lipgloss.Top,
				label.Render("ID:"),
				value.Render(interactionId),
			))
		}
	}

	title = renderBold(title)

	return "\n" + backgroundHighlight.MarginRight(6-len(level)).Render(level) + " " + title + "\n" +
		strings.Join(body, "\n")
}

func RenderLink(str string) string {
	return lipgloss.NewStyle().
		Foreground(lipgloss.Color("12")).
		Render(str)
}

func RenderDivider() string {
	return "─────────────────────────────────────────────────────\n"
}

func RenderTitle(str string) string {
	return fmt.Sprintf("\n%s\n\n", renderBold(str))
}

func RenderTip(str string) string {
	body := lipgloss.NewStyle().
		PaddingLeft(3)
	return fmt.Sprintf("\n💡 Tip\n\n%s", body.Render(str))
}

func FilterSeverityASC(original []string, severityMinLevel string) []string {
	if severityMinLevel == "" {
		return original
	}

	minLevelPointer := slices.Index(original, severityMinLevel)

	if minLevelPointer >= 0 {
		return original[minLevelPointer:]
	}

	return original
}
