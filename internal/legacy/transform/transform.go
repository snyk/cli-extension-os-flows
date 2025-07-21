package transform

import (
	"bytes"
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
	UniqueCount    int32
	DepCount       int
	ErrFactory     *errors.ErrorFactory
}

// ProcessProblemForVuln is responsible for decorating the vulnerability with information provided
// by the problems in the finding.
func ProcessProblemForVuln(
	vuln *definitions.Vulnerability,
	prob *testapi.Problem,
) error {
	disc, err := prob.Discriminator()
	if err != nil {
		return fmt.Errorf("getting problem discriminator: %w", err)
	}

	switch disc {
	case string(testapi.SnykVuln):
		snykProblemVuln, err := prob.AsSnykVulnProblem()
		if err != nil {
			return fmt.Errorf("converting problem to snyk vuln problem: %w", err)
		}
		processSnykVulnProblem(vuln, &snykProblemVuln)
	case string(testapi.Cve):
		return AddCVEIdentifier(vuln, prob)
	case string(testapi.Cwe):
		return AddCWEIdentifier(vuln, prob)
	case string(testapi.SnykLicense):
		return AddSnykLicenseIdentifier(vuln, prob)
	}
	return nil
}

func processSnykVulnProblem(vuln *definitions.Vulnerability, snykProblemVuln *testapi.SnykVulnProblem) {
	setBasicVulnInfo(vuln, snykProblemVuln)
	setVulnReferences(vuln, snykProblemVuln.References)
	setVulnSemver(vuln, snykProblemVuln)
	setEcosystem(vuln, &snykProblemVuln.Ecosystem)
	setVulnCvssInfo(vuln, snykProblemVuln)
	setVulnExploitDetails(vuln, &snykProblemVuln.ExploitDetails)
}

func setBasicVulnInfo(vuln *definitions.Vulnerability, snykProblemVuln *testapi.SnykVulnProblem) {
	vuln.Id = snykProblemVuln.Id
	vuln.CreationTime = snykProblemVuln.CreatedAt.Format(legacyTimeFormat)
	vuln.Version = snykProblemVuln.PackageVersion
	vuln.DisclosureTime = util.Ptr(snykProblemVuln.DisclosedAt.Format(legacyTimeFormat))
	vuln.PackageName = &snykProblemVuln.PackageName
	vuln.Malicious = &snykProblemVuln.IsMalicious
	vuln.ModificationTime = util.Ptr(snykProblemVuln.ModifiedAt.Format(legacyTimeFormat))
	vuln.PublicationTime = util.Ptr(snykProblemVuln.PublishedAt.Format(legacyTimeFormat))
	vuln.SocialTrendAlert = &snykProblemVuln.IsSocialMediaTrending
	if len(snykProblemVuln.Credits) > 0 {
		vuln.Credit = &snykProblemVuln.Credits
	}
	if len(snykProblemVuln.InitiallyFixedInVersions) > 0 {
		vuln.FixedIn = &snykProblemVuln.InitiallyFixedInVersions
	}
}

func setVulnReferences(vuln *definitions.Vulnerability, snykReferences []testapi.SnykvulndbReferenceLinks) {
	if len(snykReferences) == 0 {
		return
	}
	refs := make([]definitions.Reference, 0, len(snykReferences))
	for _, r := range snykReferences {
		refs = append(refs, definitions.Reference{
			Title: r.Title,
			Url:   r.Url,
		})
	}
	vuln.References = &refs
}

func getSemverInfo(affectedVersions, affectedHashes, affectedHashRanges *[]string) *definitions.SemVerInfo {
	hasAffectedVersions := affectedVersions != nil && len(*affectedVersions) > 0
	hasAffectedHashes := affectedHashes != nil && len(*affectedHashes) > 0
	hasAffectedHashRanges := affectedHashRanges != nil && len(*affectedHashRanges) > 0

	if !hasAffectedVersions && !hasAffectedHashes && !hasAffectedHashRanges {
		return nil
	}

	semver := &definitions.SemVerInfo{
		Vulnerable: []string{},
	}
	if hasAffectedVersions {
		semver.Vulnerable = *affectedVersions
	}

	var vulnerableHashes []string
	if hasAffectedHashes {
		vulnerableHashes = append(vulnerableHashes, *affectedHashes...)
	}
	if hasAffectedHashRanges {
		vulnerableHashes = append(vulnerableHashes, *affectedHashRanges...)
	}
	if len(vulnerableHashes) > 0 {
		semver.VulnerableHashes = &vulnerableHashes
	}
	return semver
}

func setVulnSemver(vuln *definitions.Vulnerability, snykProblemVuln *testapi.SnykVulnProblem) {
	vuln.Semver = getSemverInfo(snykProblemVuln.AffectedVersions, snykProblemVuln.AffectedHashes, snykProblemVuln.AffectedHashRanges)
}

func setLicenseSemver(v *definitions.Vulnerability, license *testapi.SnykLicenseProblem) {
	v.Semver = getSemverInfo(license.AffectedVersions, license.AffectedHashes, license.AffectedHashRanges)
}

func setEcosystem(vuln *definitions.Vulnerability, ecosystem *testapi.SnykvulndbPackageEcosystem) {
	ecoDisc, err := ecosystem.Discriminator()
	if err != nil {
		return
	}
	switch ecoDisc {
	case string(testapi.Build):
		if eco, err := ecosystem.AsSnykvulndbBuildPackageEcosystem(); err == nil {
			vuln.Language = &eco.Language
			vuln.PackageManager = &eco.PackageManager
		}
	case string(testapi.Os):
		if eco, err := ecosystem.AsSnykvulndbOsPackageEcosystem(); err == nil {
			vuln.PackageManager = util.Ptr(fmt.Sprintf("%s:%s", eco.Distribution, eco.Release))
		}
	}
}

func setVulnCvssInfo(vuln *definitions.Vulnerability, snykProblemVuln *testapi.SnykVulnProblem) {
	vuln.CvssScore = util.Ptr(float32(snykProblemVuln.CvssBaseScore))
	if len(snykProblemVuln.CvssSources) == 0 {
		return
	}

	snykCvssSources := snykProblemVuln.CvssSources
	cvssSources := make([]definitions.CVSSSource, 0, len(snykCvssSources))
	cvssDetails := make([]definitions.CVSSDetail, 0)
	for _, cvss := range snykCvssSources {
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
}

func setVulnExploitDetails(vuln *definitions.Vulnerability, snykExploitDetails *testapi.SnykvulndbExploitDetails) {
	if snykExploitDetails == nil {
		return
	}
	vuln.ExploitDetails = &definitions.ExploitDetails{
		Sources: snykExploitDetails.Sources,
	}
	if len(snykExploitDetails.MaturityLevels) > 0 {
		maturityLevels := make([]definitions.ExploitMaturityLevel, 0, len(snykExploitDetails.MaturityLevels))
		for _, matLevel := range snykExploitDetails.MaturityLevels {
			maturityLevels = append(maturityLevels, definitions.ExploitMaturityLevel{
				Format: matLevel.Format,
				Level:  matLevel.Level,
				Type:   string(matLevel.Type),
			})
		}
		vuln.ExploitDetails.MaturityLevels = maturityLevels
	}
}

// ProcessLocationForVuln is responsible for decorating the legacy vulnerability
// with information from the finding's location data.
func ProcessLocationForVuln(
	vuln *definitions.Vulnerability,
	loc *testapi.FindingLocation,
) error {
	locDisc, err := loc.Discriminator()
	if err != nil {
		return fmt.Errorf("getting location discriminator: %w", err)
	}
	switch locDisc {
	case string(testapi.Source):
		_, err = loc.AsSourceLocation()
		if err != nil {
			return fmt.Errorf("converting location to source location: %w", err)
		}
	case string(testapi.PackageLocationTypePackage):
		//nolint:govet // shadowing err is ok
		l, err := loc.AsPackageLocation()
		if err != nil {
			return fmt.Errorf("converting location to package location: %w", err)
		}
		vuln.Version = l.Package.Version
		vuln.Name = l.Package.Name
	case string(testapi.OtherLocationTypeOther):
		_, err = loc.AsOtherLocation()
		if err != nil {
			return fmt.Errorf("converting location to other location: %w", err)
		}
	}
	return nil
}

// ProcessEvidenceForFinding extracts the dependency lineage for the vulnerability
// from the evidence provided in the finding and returns an ordered list.
func ProcessEvidenceForFinding(ev *testapi.Evidence) ([]string, error) {
	var dependencyPath []string
	evDisc, err := ev.Discriminator()
	if err != nil {
		return nil, fmt.Errorf("getting evidence discriminator: %w", err)
	}
	if evDisc == string(testapi.DependencyPath) {
		depPathEvidence, err := ev.AsDependencyPathEvidence()
		if err != nil {
			return nil, fmt.Errorf("converting evidence to dependency path evidence: %w", err)
		}
		for _, dep := range depPathEvidence.Path {
			dependencyPath = append(dependencyPath, fmt.Sprintf("%s@%s", dep.Name, dep.Version))
		}
	}
	return dependencyPath, nil
}

// FindingToLegacyVuln is the beginning of the workflow in converting a snyk schema finding into
// a legacy vulnerability to provide legacy json outputs.
func FindingToLegacyVuln(finding *testapi.FindingData) (*definitions.Vulnerability, error) {
	vuln := definitions.Vulnerability{Description: finding.Attributes.Description}
	for i := range finding.Attributes.Problems {
		err := ProcessProblemForVuln(&vuln, &finding.Attributes.Problems[i])
		if err != nil {
			return nil, fmt.Errorf("handling problem for finding: %w", err)
		}
	}

	for i := range finding.Attributes.Locations {
		err := ProcessLocationForVuln(&vuln, &finding.Attributes.Locations[i])
		if err != nil {
			return nil, fmt.Errorf("processing location for finding: %w", err)
		}
	}

	vuln.From = []string{}
	for i := range finding.Attributes.Evidence {
		depPath, err := ProcessEvidenceForFinding(&finding.Attributes.Evidence[i])
		if err != nil {
			return nil, fmt.Errorf("processing evidence for finding: %w", err)
		}
		vuln.From = append(vuln.From, depPath...)
	}
	vuln.Title = finding.Attributes.Title
	vuln.Severity = definitions.VulnerabilitySeverity(string(finding.Attributes.Rating.Severity))
	if finding.Attributes.Risk.RiskScore != nil {
		vuln.RiskScore = &finding.Attributes.Risk.RiskScore.Value
	}

	return &vuln, nil
}

// ConvertSnykSchemaFindingsToLegacyJSON is a function that converts snyk schema findings into
// the legacy json structure for the snyk cli.
func ConvertSnykSchemaFindingsToLegacyJSON(params *SnykSchemaToLegacyParams) (json.RawMessage, error) {
	subject := params.TestResult.GetTestSubject()
	depGraphSubject, err := subject.AsDepGraphSubject()
	if err != nil {
		return nil, params.ErrFactory.NewLegacyJSONTransformerError(fmt.Errorf("marshaling to json: %w", err))
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
		UniqueCount:       params.UniqueCount,
		DependencyCount:   int64(params.DepCount),
		Vulnerabilities:   []definitions.Vulnerability{},
		Ok:                len(params.Findings) == 0,
		Filtered: definitions.Filtered{
			Ignore: make([]definitions.Vulnerability, 0),
			Patch:  make([]string, 0),
		},
	}

	for i := range params.Findings {
		//nolint:govet // it's ok to shadow err
		vuln, err := FindingToLegacyVuln(&params.Findings[i])
		if err != nil {
			return nil, params.ErrFactory.NewLegacyJSONTransformerError(fmt.Errorf("converting finding to legacy vuln: %w", err))
		}

		// The package manager can be specific to the vulnerability. If it's not set,
		// fall back to the one from the root of the dependency graph.
		if vuln.PackageManager == nil {
			vuln.PackageManager = &params.PackageManager
		}
		res.Vulnerabilities = append(res.Vulnerabilities, *vuln)
	}

	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(&res)
	if err != nil {
		return nil, params.ErrFactory.NewLegacyJSONTransformerError(fmt.Errorf("marshaling to json: %w", err))
	}
	// encoder.Encode adds a newline, which we trim to match Marshal's behavior.
	return bytes.TrimRight(buffer.Bytes(), "\n"), nil
}

// AddCVEIdentifier takes a (supposed) cve problem and extracts its identifier to
// add to the vulnerability.
func AddCVEIdentifier(v *definitions.Vulnerability, prob *testapi.Problem) error {
	ensureVulnHasIdentifiers(v)
	disc, err := prob.Discriminator()
	if err != nil {
		return fmt.Errorf("getting discriminator for cve problem")
	}
	if disc != string(testapi.Cve) {
		return fmt.Errorf("adding different kind of problem as a cve identifier")
	}
	cve, err := prob.AsCveProblem()
	if err != nil {
		return fmt.Errorf("converting problem to cve: %w", err)
	}
	v.Identifiers.CVE = append(v.Identifiers.CVE, cve.Id)
	return nil
}

// AddCWEIdentifier takes a (supposed) cwe problem and extracts its identifier to
// add to the vulnerability.
func AddCWEIdentifier(v *definitions.Vulnerability, prob *testapi.Problem) error {
	ensureVulnHasIdentifiers(v)
	disc, err := prob.Discriminator()
	if err != nil {
		return fmt.Errorf("getting discriminator for cwe problem")
	}
	if disc != string(testapi.Cwe) {
		return fmt.Errorf("adding different kind of problem as a cwe identifier")
	}
	cwe, err := prob.AsCweProblem()
	if err != nil {
		return fmt.Errorf("converting problem to cwe: %w", err)
	}
	v.Identifiers.CWE = append(v.Identifiers.CWE, cwe.Id)
	return nil
}

// AddSnykLicenseIdentifier takes a (supposed) snyk license problem and extracts various fields
// into the vulnerability.
func AddSnykLicenseIdentifier(v *definitions.Vulnerability, prob *testapi.Problem) error {
	disc, err := prob.Discriminator()
	if err != nil {
		return fmt.Errorf("getting discriminator for license problem")
	}
	if disc != string(testapi.SnykLicense) {
		return fmt.Errorf("adding different kind of problem as a snyk license identifier")
	}
	license, err := prob.AsSnykLicenseProblem()
	if err != nil {
		return fmt.Errorf("converting problem to snyk license: %w", err)
	}

	setBasicLicenseInfo(v, &license)
	setEcosystem(v, &license.Ecosystem)
	setLicenseSemver(v, &license)
	return nil
}

func setBasicLicenseInfo(v *definitions.Vulnerability, license *testapi.SnykLicenseProblem) {
	v.CreationTime = license.CreatedAt.Format(legacyTimeFormat)
	v.PublicationTime = util.Ptr(license.PublishedAt.Format(legacyTimeFormat))
	v.Id = license.Id
	v.Name = license.PackageName
	v.Version = license.PackageVersion
	v.Severity = definitions.VulnerabilitySeverity(license.Severity)
	licenseType := definitions.VulnerabilityType("license")
	v.Type = &licenseType
	v.License = &license.License
	v.PackageName = &license.PackageName
}

func ensureVulnHasIdentifiers(v *definitions.Vulnerability) {
	if v.Identifiers == nil {
		v.Identifiers = &definitions.Identifiers{CVE: []string{}, CWE: []string{}}
	}
}
