package transform

import (
	"encoding/json"
	"fmt"

	"github.com/snyk/cli-extension-os-flows/internal/errors"
	"github.com/snyk/cli-extension-os-flows/internal/legacy/definitions"
	"github.com/snyk/cli-extension-os-flows/internal/util"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
)

const (
	cvssVer3     = "3.1"
	snykAssigner = "Snyk"

	legacyTimeFormat = "2006-01-02T15:04:05.000000Z"
)

// SnykSchemaToLegacyParams is a struct to encapsulate necessary values to the
// ConvertSnykSchemaFindingsToLegacyJSON function.
type SnykSchemaToLegacyParams struct {
	Findings       []testapi.FindingData
	TestResult     testapi.TestResult
	ProjectName    string
	PackageManager string
	CurrentDir     string
	DepCount       int
	ErrFactory     *errors.ErrorFactory
}

// ConvertSnykSchemaFindingsToLegacyJSON is a function that converts snyk schema findings into
// the legacy json structure for the snyk cli.
//
//nolint:gocyclo // some things are just complex
func ConvertSnykSchemaFindingsToLegacyJSON(params *SnykSchemaToLegacyParams) (json.RawMessage, error) {
	subject := params.TestResult.GetTestSubject()
	depGraphSubject, err := subject.AsDepGraphSubject()
	if err != nil {
		panic(err)
	}

	var path string
	if len(depGraphSubject.Locator.Paths) > 0 {
		path = depGraphSubject.Locator.Paths[0]
	}

	res := definitions.LegacyVulnerabilityResponse{
		ProjectName:       params.ProjectName,
		Path:              params.CurrentDir,
		PackageManager:    params.PackageManager,
		DisplayTargetFile: path,
		DependencyCount:   int64(params.DepCount),
		Vulnerabilities:   []definitions.Vulnerability{},
	}

	for _, finding := range params.Findings {
		vuln := definitions.Vulnerability{Description: finding.Attributes.Description}
		for _, problem := range finding.Attributes.Problems {
			//nolint:govet // shadowing err is ok
			disc, err := problem.Discriminator()
			if err != nil {
				return nil, params.ErrFactory.NewLegacyJSONTransformerError(fmt.Errorf("getting problem discriminator: %w", err))
			}
			switch disc {
			case string(testapi.SnykVuln):
				snykProblemVuln, err := problem.AsSnykVulnProblem()
				if err != nil {
					return nil, params.ErrFactory.NewLegacyJSONTransformerError(fmt.Errorf("converting problem to snyk vuln problem: %w", err))
				}
				vuln.Id = snykProblemVuln.Id
				vuln.CreationTime = snykProblemVuln.CreatedAt.Format(legacyTimeFormat)
				vuln.CvssScore = util.Ptr(float32(snykProblemVuln.CvssBaseScore))
				vuln.Version = snykProblemVuln.PackageVersion
				vuln.DisclosureTime = util.Ptr(snykProblemVuln.DisclosedAt.Format(legacyTimeFormat))
				vuln.PackageName = util.Ptr(snykProblemVuln.PackageName)

				cvssSources := []definitions.CVSSSource{}
				cvssDetails := []definitions.CVSSDetail{}
				for _, cvss := range snykProblemVuln.CvssSources {
					if cvss.CvssVersion == cvssVer3 && cvss.Assigner == snykAssigner {
						vuln.CVSSv3 = util.Ptr(cvss.Vector)
					}
					cvssSource := definitions.CVSSSource{
						Assigner:         util.Ptr(cvss.Assigner),
						BaseScore:        util.Ptr(float32(cvss.BaseScore)),
						CvssVersion:      util.Ptr(cvss.CvssVersion),
						ModificationTime: util.Ptr(cvss.ModifiedAt.Format(legacyTimeFormat)),
						Severity:         util.Ptr(string(cvss.Severity)),
						Type:             util.Ptr(string(cvss.Type)),
						Vector:           util.Ptr(cvss.Vector),
					}
					cvssSources = append(cvssSources, cvssSource)

					if cvss.Assigner != snykAssigner && cvss.CvssVersion == cvssVer3 {
						cvssDetails = append(cvssDetails, definitions.CVSSDetail{
							Assigner:         *cvssSource.Assigner,
							CvssV3BaseScore:  cvssSource.BaseScore,
							CvssV3Vector:     cvssSource.Vector,
							ModificationTime: cvssSource.ModificationTime,
							Severity:         cvssSource.Severity,
						})
					}
				}
				vuln.CvssSources = &cvssSources
				vuln.CvssDetails = &cvssDetails
				vuln.ExploitDetails = &definitions.ExploitDetails{
					Sources: snykProblemVuln.ExploitDetails.Sources,
				}
				if len(snykProblemVuln.ExploitDetails.MaturityLevels) > 0 {
					for _, matLevel := range snykProblemVuln.ExploitDetails.MaturityLevels {
						vuln.ExploitDetails.MaturityLevels = append(vuln.ExploitDetails.MaturityLevels, definitions.ExploitMaturityLevel{
							Format: matLevel.Format,
							Level:  matLevel.Level,
							Type:   string(matLevel.Type),
						})
					}
				}
			case string(testapi.Cve):
				err := addCVEIdentifier(&vuln, problem)
				if err != nil {
					return nil, params.ErrFactory.NewLegacyJSONTransformerError(err)
				}
			case string(testapi.Cwe):
				err := addCWEIdentifier(&vuln, problem)
				if err != nil {
					return nil, params.ErrFactory.NewLegacyJSONTransformerError(err)
				}
			}
		}

		for _, location := range finding.Attributes.Locations {
			//nolint:govet // shadowing err is ok
			locDisc, err := location.Discriminator()
			if err != nil {
				return nil, params.ErrFactory.NewLegacyJSONTransformerError(fmt.Errorf("getting location discriminator: %w", err))
			}
			switch locDisc {
			case string(testapi.Source):
				_, err = location.AsSourceLocation()
				if err != nil {
					return nil, params.ErrFactory.NewLegacyJSONTransformerError(fmt.Errorf("converting location to source location: %w", err))
				}
			case string(testapi.PackageLocationTypePackage):
				//nolint:govet // shadowing err is ok
				l, err := location.AsPackageLocation()
				if err != nil {
					return nil, params.ErrFactory.NewLegacyJSONTransformerError(fmt.Errorf("converting location to package location: %w", err))
				}
				vuln.Version = l.Package.Version
				vuln.Name = l.Package.Name
			case string(testapi.OtherLocationTypeOther):
				_, err = location.AsOtherLocation()
				if err != nil {
					return nil, params.ErrFactory.NewLegacyJSONTransformerError(fmt.Errorf("converting location to other location: %w", err))
				}
			}
		}

		vuln.From = []string{}

		for _, ev := range finding.Attributes.Evidence {
			//nolint:govet // shadowing err is ok
			evDisc, err := ev.Discriminator()
			if err != nil {
				return nil, params.ErrFactory.NewLegacyJSONTransformerError(fmt.Errorf("getting evidence discriminator: %w", err))
			}
			if evDisc == string(testapi.DependencyPath) {
				depPathEvidence, err := ev.AsDependencyPathEvidence()
				if err != nil {
					return nil, params.ErrFactory.NewLegacyJSONTransformerError(fmt.Errorf("converting evidence to dependency path evidence: %w", err))
				}
				for _, dep := range depPathEvidence.Path {
					vuln.From = append(vuln.From, fmt.Sprintf("%s@%s", dep.Name, dep.Version))
				}
			}
		}
		vuln.Title = finding.Attributes.Title
		vuln.Severity = definitions.VulnerabilitySeverity(string(finding.Attributes.Rating.Severity))
		if finding.Attributes.Risk.RiskScore != nil {
			vuln.RiskScore = &finding.Attributes.Risk.RiskScore.Value
		}

		// TODO: does vuln.packageManager vary by finding or is it from root depGraph's pkgManager?
		vuln.PackageManager = &params.PackageManager

		res.Vulnerabilities = append(res.Vulnerabilities, vuln)
	}
	jsonBytes, err := json.Marshal(res)
	if err != nil {
		return nil, params.ErrFactory.NewLegacyJSONTransformerError(fmt.Errorf("marshaling to json: %w", err))
	}
	return jsonBytes, nil
}

func addCVEIdentifier(v *definitions.Vulnerability, prob testapi.Problem) error {
	cve, err := prob.AsCveProblem()
	if err != nil {
		return fmt.Errorf("converting problem to cve: %w", err)
	}
	ensureVulnHasIdentifiers(v)
	v.Identifiers.CVE = append(v.Identifiers.CVE, cve.Id)
	return nil
}

func addCWEIdentifier(v *definitions.Vulnerability, prob testapi.Problem) error {
	cwe, err := prob.AsCweProblem()
	if err != nil {
		return fmt.Errorf("converting problem to cwe: %w", err)
	}
	ensureVulnHasIdentifiers(v)
	v.Identifiers.CWE = append(v.Identifiers.CWE, cwe.Id)
	return nil
}

func ensureVulnHasIdentifiers(v *definitions.Vulnerability) {
	if v.Identifiers == nil {
		v.Identifiers = &definitions.Identifiers{CVE: []string{}, CWE: []string{}}
	}
}
