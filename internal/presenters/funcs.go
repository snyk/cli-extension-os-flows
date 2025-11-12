package presenters

import (
	"bytes"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/snyk/cli-extension-os-flows/internal/remediation"
)

const (
	notApplicable = "N/A"
	bulletPoint   = "○"
)

// add returns the sum of two integers.
func add(a, b int) int {
	return a + b
}

// sub returns the difference of two integers.
func sub(a, b int) int {
	return a - b
}

// hasField returns a function that checks if an object has a field at the given path.
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

// getVulnInfoURL returns the vulnerability information URL for a finding.
func getVulnInfoURL(finding testapi.FindingData) string {
	if finding.Attributes != nil {
		for _, problem := range finding.Attributes.Problems {
			disc, err := problem.Discriminator()
			if err != nil {
				continue
			}

			switch disc {
			case string(testapi.SnykVuln):
				if p, err := problem.AsSnykVulnProblem(); err == nil {
					return "https://snyk.io/vuln/" + p.Id
				}
			case string(testapi.SnykLicense):
				if p, err := problem.AsSnykLicenseProblem(); err == nil {
					return "https://snyk.io/vuln/" + p.Id
				}
			}
		}
	}
	return ""
}

const (
	packageVersionFormat = "%s@%s"
)

// FormatPathsCount returns " and X other path(s)" for multiple paths, or "" for 0-1 paths.
func FormatPathsCount(paths []string) string {
	if len(paths) <= 1 {
		return ""
	}

	additionalCount := len(paths) - 1
	countStr := pathCountStyle.Render(strconv.Itoa(additionalCount))

	if additionalCount == 1 {
		return fmt.Sprintf(" and %s other path", countStr)
	}
	return fmt.Sprintf(" and %s other paths", countStr)
}

// GetIntroducedThroughPaths returns the list of dependency paths for a finding.
func GetIntroducedThroughPaths(finding testapi.FindingData) []string {
	if finding.Attributes == nil || len(finding.Attributes.Evidence) == 0 {
		return nil
	}

	var paths []string
	for _, evidence := range finding.Attributes.Evidence {
		if depPathEvidence, err := evidence.AsDependencyPathEvidence(); err == nil {
			var parts []string
			for _, pkg := range depPathEvidence.Path {
				parts = append(parts, fmt.Sprintf(packageVersionFormat, pkg.Name, pkg.Version))
			}
			if len(parts) > 0 {
				paths = append(paths, strings.Join(parts, " > "))
			}
		}
	}
	return paths
}

func getRemediationIntroducedByPaths(vip *remediation.VulnerabilityInPackage) []string {
	var paths []string
	for _, packagePath := range vip.IntroducedThrough {
		var parts []string
		for _, pkg := range packagePath {
			parts = append(parts, fmt.Sprintf(packageVersionFormat, pkg.Name, pkg.Version))
		}
		if len(parts) > 0 {
			paths = append(paths, strings.Join(parts, " > "))
		}
	}
	return paths
}

// getIntroducedBy returns the direct dependency that introduced the vulnerability.
func getIntroducedBy(finding testapi.FindingData) string {
	if finding.Attributes == nil || len(finding.Attributes.Evidence) == 0 {
		return ""
	}

	for _, evidence := range finding.Attributes.Evidence {
		if depPathEvidence, err := evidence.AsDependencyPathEvidence(); err == nil {
			if len(depPathEvidence.Path) > 0 {
				// The first element in the path is the direct dependency from the root.
				pkg := depPathEvidence.Path[0]
				return fmt.Sprintf(packageVersionFormat, pkg.Name, pkg.Version)
			}
		}
	}

	return ""
}

// getReachability returns the reachability status for a finding.
func getReachability(finding testapi.FindingData) string {
	if finding.Attributes == nil || len(finding.Attributes.Evidence) == 0 {
		return notApplicable
	}
	for _, evidence := range finding.Attributes.Evidence {
		evDisc, err := evidence.Discriminator()
		if err != nil {
			continue
		}

		if evDisc == string(testapi.Reachability) {
			reachEvidence, err := evidence.AsReachabilityEvidence()
			if err != nil {
				continue
			}

			switch reachEvidence.Reachability {
			case testapi.ReachabilityTypeFunction:
				return "Reachable"
			case testapi.ReachabilityTypeNoInfo:
				return "No Path Found"
			default:
				return notApplicable
			}
		}
	}
	return notApplicable
}

// getFromConfig returns a function that retrieves configuration values.
func getFromConfig(config configuration.Configuration) func(key string) string {
	return func(key string) string {
		if config.GetBool(key) {
			return "true"
		}
		return config.GetString(key)
	}
}

// renderTemplateToString returns a function that renders a template to a string.
func renderTemplateToString(tmpl *template.Template) func(name string, data interface{}) (string, error) {
	return func(name string, data interface{}) (string, error) {
		var buf bytes.Buffer
		err := tmpl.ExecuteTemplate(&buf, name, data)
		if err != nil {
			return "", fmt.Errorf("failed to execute template %s: %w", name, err)
		}
		return buf.String(), nil
	}
}

// sortFindingBy sorts findings by a specified field path using the given order.
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

// filteredFinding takes a filter function and applies it to a list of findings, it will return findings that match the filter function.
func filterFinding(cmpFunc func(any) bool, findings []testapi.FindingData) (filteredFindings []testapi.FindingData) {
	for _, finding := range findings {
		if cmpFunc(finding) {
			filteredFindings = append(filteredFindings, finding)
		}
	}

	return filteredFindings
}

// isOpenFinding returns a function that checks if a finding is open.
func isOpenFinding() func(obj any) bool {
	return func(obj any) bool {
		finding, ok := obj.(testapi.FindingData)
		if !ok {
			return false
		}
		// Treat findings as open unless they are explicitly ignored.
		// Pending ignore approvals and other statuses remain visible as open issues.
		if finding.Attributes == nil || finding.Attributes.Suppression == nil {
			return true
		}
		return finding.Attributes.Suppression.Status != testapi.SuppressionStatusIgnored
	}
}

// isPendingFinding returns a function that checks if a finding is pending.
func isPendingFinding() func(obj any) bool {
	return func(obj any) bool {
		finding, ok := obj.(testapi.FindingData)
		if !ok {
			return false
		}
		return finding.Attributes.Suppression != nil && finding.Attributes.Suppression.Status == testapi.SuppressionStatusPendingIgnoreApproval
	}
}

// isIgnoredFinding returns a function that checks if a finding is ignored.
func isIgnoredFinding() func(obj any) bool {
	return func(obj any) bool {
		finding, ok := obj.(testapi.FindingData)
		if !ok {
			return false
		}
		return finding.Attributes.Suppression != nil && finding.Attributes.Suppression.Status == testapi.SuppressionStatusIgnored
	}
}

// isLicenseFinding returns true if the finding is a license finding.
func isLicenseFinding(finding testapi.FindingData) bool {
	if finding.Attributes != nil {
		for _, problem := range finding.Attributes.Problems {
			disc, err := problem.Discriminator()
			if err == nil && disc == string(testapi.SnykLicense) {
				return true
			}
		}
	}
	return false
}

// getLicenseInstructions returns license instructions for a license finding.
func getLicenseInstructions(finding testapi.FindingData) string {
	if finding.Attributes == nil {
		return ""
	}

	for _, problem := range finding.Attributes.Problems {
		disc, err := problem.Discriminator()
		if err != nil {
			continue
		}

		if disc != string(testapi.SnykLicense) {
			continue
		}

		p, err := problem.AsSnykLicenseProblem()
		if err != nil {
			continue
		}

		if len(p.Instructions) == 0 {
			continue
		}

		instructions := buildInstructionsList(p.Instructions)
		if len(instructions) > 0 {
			return "\n" + strings.Join(instructions, "\n")
		}
	}
	return ""
}

// buildInstructionsList formats license instructions prefixing with a bullet point and license name.
func buildInstructionsList(instructionsList []testapi.SnykvulndbLicenseInstructions) []string {
	instructions := make([]string, 0, len(instructionsList))

	for _, inst := range instructionsList {
		if inst.Content == "" {
			continue
		}
		instructions = append(instructions, fmt.Sprintf("   %s for %s: %s", bulletPoint, inst.License, inst.Content))
	}
	return instructions
}

// isLicenseFindingFilter returns a filter function that checks if a finding is a license finding.
func isLicenseFindingFilter() func(obj any) bool {
	return func(obj any) bool {
		finding, ok := obj.(testapi.FindingData)
		if !ok {
			return false
		}
		return isLicenseFinding(finding)
	}
}

// isNotLicenseFindingFilter returns a function that checks if a finding is not a license finding.
func isNotLicenseFindingFilter() func(obj any) bool {
	return func(obj any) bool {
		finding, ok := obj.(testapi.FindingData)
		if !ok {
			return true
		}
		isLicense := isLicenseFinding(finding)
		return !isLicense
	}
}

// hasSuppression checks if a finding has any suppression.
func hasSuppression(finding testapi.FindingData) bool {
	if finding.Attributes == nil || finding.Attributes.Suppression == nil {
		return false
	}

	// Treat as suppressed unless the suppression status is "other" (treating as rejected).
	return finding.Attributes.Suppression.Status != testapi.SuppressionStatusOther
}

// getCliTemplateFuncMap returns the template function map for CLI rendering.
func getCliTemplateFuncMap(tmpl *template.Template) template.FuncMap {
	fnMap := template.FuncMap{}
	fnMap["box"] = func(s string) string { return boxStyle.Render(s) }
	fnMap["toUpperCase"] = func(obj any) string {
		if reflect.TypeOf(obj).Kind() == reflect.String {
			stringObj := reflect.ValueOf(obj).String()
			return strings.ToUpper(stringObj)
		}
		panic("invalid type in toUpperCase call")
	}
	fnMap["capitalize"] = func(obj any) string {
		if reflect.TypeOf(obj).Kind() == reflect.String {
			stringObj := reflect.ValueOf(obj).String()
			caser := cases.Title(language.English)
			return caser.String(stringObj)
		}
		panic("invalid type in capitalize call")
	}
	fnMap["renderInSeverityColor"] = renderInSeverityColor
	fnMap["renderGreen"] = renderGreen
	fnMap["renderGray"] = renderGray
	fnMap["bold"] = renderBold
	fnMap["tip"] = func(s string) string {
		return RenderTip(s + "\n")
	}
	fnMap["divider"] = RenderDivider
	fnMap["title"] = RenderTitle
	fnMap["renderToString"] = renderTemplateToString(tmpl)
	fnMap["isLicenseFindingFilter"] = isLicenseFindingFilter
	fnMap["isNotLicenseFindingFilter"] = isNotLicenseFindingFilter
	fnMap["isOpenFinding"] = isOpenFinding
	fnMap["isPendingFinding"] = isPendingFinding
	fnMap["isIgnoredFinding"] = isIgnoredFinding
	fnMap["hasSuppression"] = hasSuppression
	fnMap["collectAllFindings"] = collectAllFindings
	fnMap["summaryData"] = summaryData
	fnMap["shouldShowAggregateSummary"] = shouldShowAggregateSummary
	return fnMap
}

// SummaryData holds findings and severity order for rendering summary counts.
type SummaryData struct {
	Findings      []testapi.FindingData
	SeverityOrder []string
}

func summaryData(findings []testapi.FindingData, severityOrder []string) SummaryData {
	return SummaryData{
		Findings:      findings,
		SeverityOrder: severityOrder,
	}
}

// collectAllFindings combines findings from multiple project results into a single slice.
func collectAllFindings(results []*UnifiedProjectResult) []testapi.FindingData {
	totalFindings := 0
	for _, result := range results {
		totalFindings += len(result.Findings)
	}

	allFindings := make([]testapi.FindingData, 0, totalFindings)
	for _, result := range results {
		allFindings = append(allFindings, result.Findings...)
	}

	return allFindings
}

// shouldShowAggregateSummary determines if an aggregate summary should be shown
// based on the number of results.
func shouldShowAggregateSummary(results []*UnifiedProjectResult) bool {
	return len(results) > 1
}

// getDefaultTemplateFuncMap returns the default template function map.
func getDefaultTemplateFuncMap(config configuration.Configuration, ri runtimeinfo.RuntimeInfo) template.FuncMap {
	getSourceLocation := func(loc testapi.FindingLocation) *testapi.SourceLocation {
		if sl, err := loc.AsSourceLocation(); err == nil {
			return &sl
		}
		return nil
	}
	getFindingID := func(finding testapi.FindingData) string {
		if finding.Attributes != nil {
			for _, problem := range finding.Attributes.Problems {
				disc, err := problem.Discriminator()
				if err != nil {
					continue
				}

				switch disc {
				case string(testapi.SnykVuln):
					if p, err := problem.AsSnykVulnProblem(); err == nil {
						return p.Id
					}
				case string(testapi.SnykLicense):
					if p, err := problem.AsSnykLicenseProblem(); err == nil {
						return p.Id
					}
				}
			}
		}

		// fallback to top-level ID if no problem ID is found
		if finding.Id != nil {
			return finding.Id.String()
		}
		return notApplicable
	}

	defaultMap := template.FuncMap{}
	defaultMap["getRuntimeInfo"] = func(key string) string { return getRuntimeInfo(key, ri) }
	defaultMap["getValueFromConfig"] = getFromConfig(config)
	defaultMap["sortFindingBy"] = sortFindingBy
	defaultMap["getFieldValueFrom"] = getFieldValueFrom
	defaultMap["getVulnInfoURL"] = getVulnInfoURL
	defaultMap["getIntroducedThroughPaths"] = GetIntroducedThroughPaths

	defaultMap["getIntroducedBy"] = getIntroducedBy
	defaultMap["getReachability"] = getReachability
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
	defaultMap["formatPathsCount"] = FormatPathsCount
	defaultMap["formatDatetime"] = formatDatetime
	defaultMap["getSourceLocation"] = getSourceLocation
	defaultMap["getFindingId"] = getFindingID
	defaultMap["isLicenseFinding"] = isLicenseFinding
	defaultMap["getLicenseInstructions"] = getLicenseInstructions
	defaultMap["hasPrefix"] = strings.HasPrefix
	defaultMap["constructDisplayPath"] = constructDisplayPath
	defaultMap["filterByIssueType"] = filterByIssueType
	defaultMap["getSummaryResultsByIssueType"] = getSummaryResultsByIssueType
	defaultMap["getIssueCountsTotal"] = getIssueCountsTotal
	defaultMap["getIssueCountsOpen"] = getIssueCountsOpen
	defaultMap["getIssueCountsIgnored"] = getIssueCountsIgnored

	// This will compute the OS specific remediation summary
	defaultMap["getRemediationIntroducedByPaths"] = getRemediationIntroducedByPaths

	defaultMap["getRemediationSummary"] = func(findings []testapi.FindingData) remediation.Summary {
		remFindings, err := remediation.ShimFindingsToRemediationFindings(findings)
		if err != nil {
			panic(err)
		}

		summary, err := remediation.FindingsToRemediationSummary(remFindings)
		if err != nil {
			panic(err)
		}

		return summary
	}
	return defaultMap
}

func getIssueCountsTotal(results []json_schemas.TestSummaryResult) (total int) {
	for _, res := range results {
		total += res.Total
	}
	return total
}

func getIssueCountsOpen(results []json_schemas.TestSummaryResult) (open int) {
	for _, res := range results {
		open += res.Open
	}
	return open
}

func getIssueCountsIgnored(results []json_schemas.TestSummaryResult) (ignored int) {
	for _, res := range results {
		ignored += res.Ignored
	}
	return ignored
}

// filterByIssueType filters a list of finding summary results by issue type.
func filterByIssueType(issueType string, summary *json_schemas.TestSummary) []json_schemas.TestSummaryResult {
	if summary.Type == issueType {
		return summary.Results
	}
	return []json_schemas.TestSummaryResult{}
}

// getSummaryResultsByIssueType computes summary results for a specific issue type from findings.
// issueType can be "vulnerability" or "license".
func getSummaryResultsByIssueType(issueType string, findings []testapi.FindingData, orderAsc []string) []json_schemas.TestSummaryResult {
	if len(findings) == 0 {
		return []json_schemas.TestSummaryResult{}
	}

	// Prepare counters by severity
	totalBySeverity := map[string]int{}
	openBySeverity := map[string]int{}
	ignoredBySeverity := map[string]int{}

	for _, f := range findings {
		// Determine category membership
		isLicense := isLicenseFinding(f)
		if issueType == "license" && !isLicense {
			continue
		}
		if issueType == "vulnerability" && isLicense {
			continue
		}

		severity := getFieldValueFrom(f, "Attributes.Rating.Severity")
		if severity == "" {
			// Skip if we cannot determine severity
			continue
		}

		totalBySeverity[severity]++

		// Determine suppression state: only explicit "ignored" should reduce open counts.
		isIgnored := false
		isOpen := true
		if f.Attributes != nil && f.Attributes.Suppression != nil {
			isIgnored = f.Attributes.Suppression.Status == testapi.SuppressionStatusIgnored
			isOpen = !isIgnored
		}

		if isOpen {
			openBySeverity[severity]++
		}
		if isIgnored {
			ignoredBySeverity[severity]++
		}
	}

	// Build results in the provided order, but only include severities that appeared
	results := make([]json_schemas.TestSummaryResult, 0, len(totalBySeverity))
	for _, sev := range orderAsc {
		total := totalBySeverity[sev]
		if total == 0 {
			continue
		}
		results = append(results, json_schemas.TestSummaryResult{
			Severity: sev,
			Total:    total,
			Open:     openBySeverity[sev],
			Ignored:  ignoredBySeverity[sev],
		})
	}

	return results
}

// reverse reverses the order of elements in a slice.
func reverse(v interface{}) []interface{} {
	l, err := mustReverse(v)
	if err != nil {
		panic(err)
	}

	return l
}

// mustReverse reverses the order of elements in a slice, panicking on error.
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

// getRuntimeInfo returns runtime information for a given key.
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

// formatDatetime formats a datetime string from one format to another.
func formatDatetime(input, inputFormat, outputFormat string) string {
	datetime, err := time.Parse(inputFormat, input)
	if err != nil {
		return input
	}

	return datetime.Format(outputFormat)
}

// constructDisplayPath constructs the display path from the summary path and display target file.
func constructDisplayPath(targetDir, displayTargetFile string) string {
	if displayTargetFile == "" {
		return targetDir
	}
	return fmt.Sprintf("%s (%s)", targetDir, displayTargetFile)
}
