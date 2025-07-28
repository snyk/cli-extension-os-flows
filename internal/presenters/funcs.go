package presenters

import (
	"bytes"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"text/template"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
)

func add(a, b int) int {
	return a + b
}

func sub(a, b int) int {
	return a - b
}

func hasField(path string) func(obj any) bool {
	return func(obj any) bool {
		// Split the path into fields
		fields := strings.Split(path, ".")

		value := reflect.ValueOf(obj)
		for _, field := range fields {
			// Dereference pointers if necessary
			if value.Kind() == reflect.Ptr {
				value = value.Elem()
			}

			// Ensure the current value is a struct
			if value.Kind() != reflect.Struct {
				return false
			}

			// Retrieve the struct field by name
			value = value.FieldByName(field)
			if !value.IsValid() {
				return false
			}
		}

		// Return true if field value exists
		return value.Interface() != nil
	}
}

// getFieldValueFrom retrieves a value from a struct by a dot-separated path.
func getFieldValueFrom(data interface{}, path string) string {
	// Split the path into fields
	fields := strings.Split(path, ".")
	v := reflect.ValueOf(data)
	for _, field := range fields {
		// Dereference pointers if necessary
		for v.Kind() == reflect.Ptr {
			if v.IsNil() {
				return ""
			}
			v = v.Elem()
		}

		// Ensure the current value is a struct
		if v.Kind() != reflect.Struct {
			return ""
		}

		// Retrieve the struct field by name
		v = v.FieldByName(field)
		if !v.IsValid() {
			return ""
		}
	}

	// Dereference the final value if it's a pointer.
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return ""
		}
		v = v.Elem()
	}

	// Return the final field value
	return fmt.Sprint(v.Interface())
}

func getVulnInfoURL(finding testapi.FindingData) string {
	if len(finding.Attributes.Problems) > 0 {
		problem := finding.Attributes.Problems[0]
		if p, err := problem.AsSnykVulnProblem(); err == nil {
			return "https://snyk.io/vuln/" + p.Id
		}
		if p, err := problem.AsSnykLicenseProblem(); err == nil {
			// License issues might have a different URL structure, but for now this is a safe bet.
			return "https://snyk.io/vuln/" + p.Id
		}
	}
	return ""
}

func getIntroducedThrough(finding testapi.FindingData) string {
	if len(finding.Attributes.Evidence) > 0 {
		evidence := finding.Attributes.Evidence[0]

		// An evidence object is a union type. We need to check if it's a DependencyPathEvidence.
		if depPathEvidence, err := evidence.AsDependencyPathEvidence(); err == nil {
			var pathParts []string
			for _, pkg := range depPathEvidence.Path {
				pathParts = append(pathParts, fmt.Sprintf("%s@%s", pkg.Name, pkg.Version))
			}
			if len(pathParts) > 0 {
				return strings.Join(pathParts, " > ")
			}
		}
	}
	return ""
}

func getIntroducedBy(finding testapi.FindingData) string {
	if len(finding.Attributes.Evidence) > 0 {
		evidence := finding.Attributes.Evidence[0]
		if depPathEvidence, err := evidence.AsDependencyPathEvidence(); err == nil {
			if len(depPathEvidence.Path) > 0 {
				// The first element in the path is the direct dependency from the root.
				pkg := depPathEvidence.Path[0]
				return fmt.Sprintf("%s@%s", pkg.Name, pkg.Version)
			}
		}
	}
	return ""
}

func getFromConfig(config configuration.Configuration) func(key string) string {
	return func(key string) string {
		if config.GetBool(key) {
			return "true"
		}
		return config.GetString(key)
	}
}

func renderTemplateToString(tmpl *template.Template) func(name string, data interface{}) (string, error) {
	return func(name string, data interface{}) (string, error) {
		var buf bytes.Buffer
		err := tmpl.ExecuteTemplate(&buf, name, data)
		if err != nil {
			return "", err
		}
		return buf.String(), nil
	}
}

func renderSeverityColor(severity string) string {
	upperSeverity := strings.ToUpper(severity)
	var style lipgloss.TerminalColor
	switch {
	case strings.Contains(upperSeverity, "CRITICAL"):
		// Purple
		style = lipgloss.AdaptiveColor{Light: "13", Dark: "5"}
	case strings.Contains(upperSeverity, "HIGH"):
		// Red
		style = lipgloss.AdaptiveColor{Light: "9", Dark: "1"}
	case strings.Contains(upperSeverity, "MEDIUM"):
		// Yellow/Orange
		style = lipgloss.AdaptiveColor{Light: "11", Dark: "3"}
	default:
		style = lipgloss.NoColor{}
	}
	severityStyle := lipgloss.NewStyle().Foreground(style)
	return severityStyle.Render(severity)
}

func sortFindingBy(path string, order []string, findings []testapi.FindingData) []testapi.FindingData {
	result := make([]testapi.FindingData, 0, len(findings))
	result = append(result, findings...)

	slices.SortFunc(result, func(a, b testapi.FindingData) int {
		aVal := getFieldValueFrom(a, path)
		bVal := getFieldValueFrom(b, path)
		if aVal != bVal {
			return slices.Index(order, aVal) - slices.Index(order, bVal)
		}

		return 0
	})

	return result
}

// filteredFinding takes a filter function and applies it to a list of findings, it will return findings that match the filter function
func filterFinding(cmpFunc func(any) bool, findings []testapi.FindingData) (filteredFindings []testapi.FindingData) {
	for _, finding := range findings {
		if cmpFunc(finding) {
			filteredFindings = append(filteredFindings, finding)
		}
	}

	return filteredFindings
}

func isOpenFinding() func(obj any) bool {
	return func(obj any) bool {
		finding, ok := obj.(testapi.FindingData)
		if !ok {
			return false
		}
		// A finding is considered "open" if it has no suppression information.
		// A rejected suppression is not represented as a status, but by the absence of a suppression object.
		return finding.Attributes.Suppression == nil
	}
}

func isPendingFinding() func(obj any) bool {
	return func(obj any) bool {
		finding, ok := obj.(testapi.FindingData)
		if !ok {
			return false
		}
		return finding.Attributes.Suppression != nil && finding.Attributes.Suppression.Status == testapi.SuppressionStatusPendingIgnoreApproval
	}
}

func isIgnoredFinding() func(obj any) bool {
	return func(obj any) bool {
		finding, ok := obj.(testapi.FindingData)
		if !ok {
			return false
		}
		return finding.Attributes.Suppression != nil && finding.Attributes.Suppression.Status == testapi.SuppressionStatusIgnored
	}
}

func hasSuppression(finding testapi.FindingData) bool {
	if finding.Attributes.Suppression == nil {
		return false
	}

	// If a suppression object exists, the finding is considered suppressed (either ignored or pending).
	return true
}

func getCliTemplateFuncMap(tmpl *template.Template) template.FuncMap {
	fnMap := template.FuncMap{}
	fnMap["box"] = func(s string) string { return boxStyle.Render(s) }
	fnMap["toUpperCase"] = strings.ToUpper
	fnMap["renderInSeverityColor"] = renderSeverityColor
	fnMap["bold"] = renderBold
	fnMap["tip"] = func(s string) string {
		return RenderTip(s + "\n")
	}
	fnMap["divider"] = RenderDivider
	fnMap["title"] = RenderTitle
	fnMap["renderToString"] = renderTemplateToString(tmpl)
	fnMap["isOpenFinding"] = isOpenFinding
	fnMap["isPendingFinding"] = isPendingFinding
	fnMap["isIgnoredFinding"] = isIgnoredFinding
	fnMap["hasSuppression"] = hasSuppression
	return fnMap
}

func getDefaultTemplateFuncMap(config configuration.Configuration, ri runtimeinfo.RuntimeInfo) template.FuncMap {
	getSourceLocation := func(loc testapi.FindingLocation) *testapi.SourceLocation {
		if sl, err := loc.AsSourceLocation(); err == nil {
			return &sl
		}
		return nil
	}
	getFindingId := func(finding testapi.FindingData) string {
		if finding.Id != nil {
			return finding.Id.String()
		}
		return "N/A"
	}

	defaultMap := template.FuncMap{}
	defaultMap["getRuntimeInfo"] = func(key string) string { return getRuntimeInfo(key, ri) }
	defaultMap["getValueFromConfig"] = getFromConfig(config)
	defaultMap["sortFindingBy"] = sortFindingBy
	defaultMap["getFieldValueFrom"] = getFieldValueFrom
	defaultMap["getVulnInfoURL"] = getVulnInfoURL
	defaultMap["getIntroducedThrough"] = getIntroducedThrough
	defaultMap["getIntroducedBy"] = getIntroducedBy
	defaultMap["filterFinding"] = filterFinding
	defaultMap["hasField"] = hasField
	defaultMap["notHasField"] = func(path string) func(obj any) bool {
		return func(obj any) bool {
			return !hasField(path)(obj)
		}
	}
	defaultMap["add"] = add
	defaultMap["sub"] = sub
	defaultMap["reverse"] = reverse
	defaultMap["join"] = strings.Join
	defaultMap["formatDatetime"] = formatDatetime
	defaultMap["getSourceLocation"] = getSourceLocation
	defaultMap["getFindingId"] = getFindingId
	defaultMap["hasPrefix"] = strings.HasPrefix

	return defaultMap
}

func reverse(v interface{}) []interface{} {
	l, err := mustReverse(v)
	if err != nil {
		panic(err)
	}

	return l
}

func mustReverse(v interface{}) ([]interface{}, error) {
	tp := reflect.TypeOf(v).Kind()
	switch tp {
	case reflect.Slice, reflect.Array:
		l2 := reflect.ValueOf(v)

		l := l2.Len()
		// We do not sort in place because the incoming array should not be altered.
		nl := make([]interface{}, l)
		for i := 0; i < l; i++ {
			nl[l-i-1] = l2.Index(i).Interface()
		}

		return nl, nil
	default:
		return nil, fmt.Errorf("cannot find reverse on type %s", tp)
	}
}

func getRuntimeInfo(key string, ri runtimeinfo.RuntimeInfo) string {
	if ri == nil {
		return ""
	}

	switch strings.ToLower(key) {
	case "name":
		return ri.GetName()
	case "version":
		return ri.GetVersion()
	default:
		return ""
	}
}

func formatDatetime(input string, inputFormat string, outputFormat string) string {
	datetime, err := time.Parse(inputFormat, input)
	if err != nil {
		return input
	}

	return datetime.Format(outputFormat)
}
