package transform_test

import (
	"encoding/json"
	"testing"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/legacy/definitions"
	"github.com/snyk/cli-extension-os-flows/internal/legacy/transform"
)

var minimumFinding = testapi.FindingData{
	Attributes: &testapi.FindingAttributes{
		Rating: testapi.Rating{
			Severity: "medium",
		},
	},
}

func TestUpgradePath_WhenNotAvailable_EmptyArray(t *testing.T) {
	vuln, vulnJSON := transformFinding(t, minimumFinding)

	assert.Len(t, vuln.UpgradePath, 0)
	assert.Contains(t, vulnJSON, `"upgradePath":[]`)
}

func TestEPSSDetails_WhenNotAvailable_NotIncludedInJSON(t *testing.T) {
	vuln, vulnJSON := transformFinding(t, minimumFinding)

	assert.Nil(t, vuln.EpssDetails)
	assert.NotContains(t, vulnJSON, `"epssDetails"`)
}

func TestInsights_WhenTriageAdviceProvided_IncludedInJSON(t *testing.T) {
	finding := findingWithVulnProblem(t, &testapi.SnykVulnProblem{
		Id: "SNYK-JS-ASYNC-12239908",
		Insights: &testapi.SnykvulndbVulnInsights{
			TriageAdvice: utils.Ptr("Only exploitable when the parser runs on untrusted input."),
		},
	})

	vuln, vulnJSON := transformFinding(t, finding)

	require.NotNil(t, vuln.Insights)
	require.NotNil(t, vuln.Insights.TriageAdvice)
	assert.Equal(t, "Only exploitable when the parser runs on untrusted input.", *vuln.Insights.TriageAdvice)
	assert.Contains(t, vulnJSON, `"insights":{"triageAdvice":"Only exploitable when the parser runs on untrusted input."}`)
}

func TestInsights_WhenNotProvided_TriageAdviceIsNull(t *testing.T) {
	finding := findingWithVulnProblem(t, &testapi.SnykVulnProblem{Id: "SNYK-JS-ASYNC-12239908"})

	vuln, vulnJSON := transformFinding(t, finding)

	require.NotNil(t, vuln.Insights)
	assert.Nil(t, vuln.Insights.TriageAdvice)
	assert.Contains(t, vulnJSON, `"insights":{"triageAdvice":null}`)
}

func TestInsights_WhenVulnIsIgnored_TriageAdviceIsRetained(t *testing.T) {
	findings := loadFindings(t, "testdata/projectIgnore-findings.json")
	withTriageAdvice(t, findings, "SNYK-GOLANG-GOPKGINYAMLV2-12330650", "Reachable only from the CLI entrypoint.")

	vulns, err := transform.FindingsToLegacyVulns(findings, "package-manager", utils.Ptr(zerolog.Nop()))
	require.NoError(t, err)

	vuln := findByID("SNYK-GOLANG-GOPKGINYAMLV2-12330650", vulns)

	require.NotNil(t, vuln.IsIgnored)
	require.True(t, *vuln.IsIgnored)
	require.NotNil(t, vuln.Insights)
	require.NotNil(t, vuln.Insights.TriageAdvice)
	assert.Equal(t, "Reachable only from the CLI entrypoint.", *vuln.Insights.TriageAdvice)
}

func TestModuleName_WhenProvided_IncludedInJSON(t *testing.T) {
	finding := findingWithVulnProblem(t, &testapi.SnykVulnProblem{
		Id:         "SNYK-JS-ASYNC-12239908",
		ModuleName: utils.Ptr("async"),
	})

	vuln, vulnJSON := transformFinding(t, finding)

	require.NotNil(t, vuln.ModuleName)
	assert.Equal(t, "async", *vuln.ModuleName)
	assert.Contains(t, vulnJSON, `"moduleName":"async"`)
}

func TestModuleName_WhenNotProvided_NotIncludedInJSON(t *testing.T) {
	finding := findingWithVulnProblem(t, &testapi.SnykVulnProblem{Id: "SNYK-JS-ASYNC-12239908"})

	vuln, vulnJSON := transformFinding(t, finding)

	assert.Nil(t, vuln.ModuleName)
	assert.NotContains(t, vulnJSON, `"moduleName"`)
}

func TestFunctionsNew_WhenVulnerableFunctionsProvided_IncludedInJSON(t *testing.T) {
	finding := findingWithVulnProblem(t, &testapi.SnykVulnProblem{
		Id: "SNYK-JAVA-ORGAPACHECOMMONS-12239908",
		VulnerableFunctionsList: &[]testapi.SnykvulndbVulnerableFunction{
			{
				FunctionId: testapi.SnykvulndbVulnerableFunctionId{
					FunctionName: "toObject",
					ClassName:    utils.Ptr("org.apache.commons.beanutils.BeanUtils"),
					FilePath:     utils.Ptr("src/main/java/org/apache/commons/beanutils/BeanUtils.java"),
				},
				Versions: []string{"1.9.2", "1.9.3"},
			},
		},
	})

	vuln, vulnJSON := transformFinding(t, finding)

	require.NotNil(t, vuln.FunctionsNew)
	require.Len(t, *vuln.FunctionsNew, 1)
	fn := (*vuln.FunctionsNew)[0]
	assert.Equal(t, "toObject", fn.FunctionId.FunctionName)
	assert.Equal(t, "org.apache.commons.beanutils.BeanUtils", *fn.FunctionId.ClassName)
	assert.Equal(t, "src/main/java/org/apache/commons/beanutils/BeanUtils.java", *fn.FunctionId.FilePath)
	assert.Equal(t, []string{"1.9.2", "1.9.3"}, fn.Version)
	assert.Contains(t, vulnJSON,
		`"functions_new":[{"functionId":{"className":"org.apache.commons.beanutils.BeanUtils",`+
			`"filePath":"src/main/java/org/apache/commons/beanutils/BeanUtils.java",`+
			`"functionName":"toObject"},"version":["1.9.2","1.9.3"]}]`)
}

func TestFunctionsNew_WhenClassNameAndFilePathMissing_OmittedFromJSON(t *testing.T) {
	finding := findingWithVulnProblem(t, &testapi.SnykVulnProblem{
		Id: "SNYK-JS-ASYNC-12239908",
		VulnerableFunctionsList: &[]testapi.SnykvulndbVulnerableFunction{
			{
				FunctionId: testapi.SnykvulndbVulnerableFunctionId{FunctionName: "mapValues"},
				Versions:   []string{"2.6.3"},
			},
		},
	})

	vuln, vulnJSON := transformFinding(t, finding)

	require.NotNil(t, vuln.FunctionsNew)
	require.Len(t, *vuln.FunctionsNew, 1)
	assert.Nil(t, (*vuln.FunctionsNew)[0].FunctionId.ClassName)
	assert.Nil(t, (*vuln.FunctionsNew)[0].FunctionId.FilePath)
	assert.Contains(t, vulnJSON, `"functions_new":[{"functionId":{"functionName":"mapValues"},"version":["2.6.3"]}]`)
}

func TestFunctionsNew_WhenVersionsMissing_IsEmptyArray(t *testing.T) {
	finding := findingWithVulnProblem(t, &testapi.SnykVulnProblem{
		Id: "SNYK-JS-ASYNC-12239908",
		VulnerableFunctionsList: &[]testapi.SnykvulndbVulnerableFunction{
			{FunctionId: testapi.SnykvulndbVulnerableFunctionId{FunctionName: "mapValues"}},
		},
	})

	_, vulnJSON := transformFinding(t, finding)

	assert.Contains(t, vulnJSON, `"version":[]`)
}

func TestFunctionsNew_WhenNotProvided_EmptyArray(t *testing.T) {
	finding := findingWithVulnProblem(t, &testapi.SnykVulnProblem{Id: "SNYK-JS-ASYNC-12239908"})

	vuln, vulnJSON := transformFinding(t, finding)

	require.NotNil(t, vuln.FunctionsNew)
	assert.Empty(t, *vuln.FunctionsNew)
	assert.Contains(t, vulnJSON, `"functions_new":[]`)
}

func findingWithVulnProblem(t *testing.T, vulnProblem *testapi.SnykVulnProblem) testapi.FindingData {
	t.Helper()

	var problem testapi.Problem
	require.NoError(t, problem.FromSnykVulnProblem(*vulnProblem))

	return testapi.FindingData{
		Attributes: &testapi.FindingAttributes{
			Rating:   testapi.Rating{Severity: "medium"},
			Problems: []testapi.Problem{problem},
		},
	}
}

func withTriageAdvice(t *testing.T, findings []testapi.FindingData, vulnID, advice string) {
	t.Helper()

	for _, finding := range findings {
		for i := range finding.Attributes.Problems {
			problem := &finding.Attributes.Problems[i]

			vulnProblem, err := problem.AsSnykVulnProblem()
			if err != nil || vulnProblem.Id != vulnID {
				continue
			}

			vulnProblem.Insights = &testapi.SnykvulndbVulnInsights{TriageAdvice: utils.Ptr(advice)}
			require.NoError(t, problem.FromSnykVulnProblem(vulnProblem))

			return
		}
	}

	t.Fatalf("no snyk vuln problem with id %q in findings", vulnID)
}

func transformFinding(t *testing.T, finding testapi.FindingData) (vuln definitions.Vulnerability, vulnJSON string) {
	t.Helper()

	vulns, err := transform.FindingsToLegacyVulns([]testapi.FindingData{finding}, "package-manager", utils.Ptr(zerolog.Nop()))
	require.NoError(t, err)
	require.Len(t, vulns, 1)
	vuln = vulns[0]

	vulnBytes, err := json.Marshal(vuln)
	assert.NoError(t, err)

	return vuln, string(vulnBytes)
}

func TestMaturityLevels(t *testing.T) {
	findings := loadFindings(t, "testdata/projectIgnore-findings.json")

	vulns, err := transform.FindingsToLegacyVulns(findings, "package-manager", utils.Ptr(zerolog.Nop()))
	require.NoError(t, err)

	vuln := findByID("SNYK-GOLANG-GOPKGINYAMLV2-12330650", vulns)

	require.NotNil(t, vuln.ExploitDetails)
	require.NotEmpty(t, vuln.ExploitDetails.MaturityLevels)
	require.Equal(t, vuln.ExploitDetails.MaturityLevels[0].Level, "Not Defined")
}

func TestVulnExploit(t *testing.T) {
	findings := loadFindings(t, "testdata/groupIgnoreAndSeverityAndDotsnykAndProjectIgnore-findings.json")

	vulns, err := transform.FindingsToLegacyVulns(findings, "package-manager", utils.Ptr(zerolog.Nop()))
	require.NoError(t, err)

	vuln := findByID("SNYK-GOLANG-GOPKGINYAMLV2-12330650", vulns)

	require.NotNil(t, vuln.Exploit)
	require.Equal(t, "Not Defined", *vuln.Exploit)
}
