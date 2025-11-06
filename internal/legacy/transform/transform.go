package transform

import (
	"context"
	"fmt"

	"github.com/snyk/go-application-framework/pkg/utils"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"

	cmdutil "github.com/snyk/cli-extension-os-flows/internal/commands/util"
	"github.com/snyk/cli-extension-os-flows/internal/errors"
	"github.com/snyk/cli-extension-os-flows/internal/legacy/definitions"
	"github.com/snyk/cli-extension-os-flows/internal/remediation"
	"github.com/snyk/cli-extension-os-flows/internal/util"
)

const (
	cvssVer3     = "3.1"
	snykAssigner = "Snyk"

	legacyTimeFormat                = "2006-01-02T15:04:05.000000Z"
	logFieldDiscriminator           = "discriminator"
	errProcessEvidenceForFindingStr = "processing evidence for finding: %w"
)

// SnykSchemaToLegacyParams is a struct to encapsulate necessary values to the
// ConvertSnykSchemaFindingsToLegacy function.
type SnykSchemaToLegacyParams struct {
	Findings           []testapi.FindingData
	RemediationSummary remediation.Summary
	ProjectID          *string
	TestResult         testapi.TestResult
	OrgSlugOrID        string
	ProjectName        string
	PackageManager     string
	TargetDir          string
	UniqueCount        int32
	DepCount           int
	TargetFile         string
	DisplayTargetFile  string
	ErrFactory         *errors.ErrorFactory
	Logger             *zerolog.Logger
}

// ConvertSnykSchemaFindingsToLegacy is a function that converts snyk schema findings into
// the legacy vulnerability response structure for the snyk cli.
func ConvertSnykSchemaFindingsToLegacy(ctx context.Context, params *SnykSchemaToLegacyParams) (*definitions.LegacyVulnerabilityResponse, error) {
	if _, err := params.TestResult.GetTestSubject().AsDepGraphSubject(); err != nil {
		return nil, params.ErrFactory.NewLegacyJSONTransformerError(
			fmt.Errorf("expected a depgraph subject but got something else: %w", err))
	}

	allVulnerabilities, err := FindingsToLegacyVulns(params.Findings, params.PackageManager, params.Logger)
	if err != nil {
		return nil, params.ErrFactory.NewLegacyJSONTransformerError(fmt.Errorf("converting finding to legacy vuln: %w", err))
	}

	vulnReport := SeparateIgnoredVulnerabilities(allVulnerabilities, false)

	res := definitions.LegacyVulnerabilityResponse{
		Org:               params.OrgSlugOrID,
		ProjectId:         params.ProjectID,
		ProjectName:       params.ProjectName,
		Path:              params.TargetDir,
		PackageManager:    params.PackageManager,
		TargetFile:        &params.TargetFile,
		DisplayTargetFile: params.DisplayTargetFile,
		UniqueCount:       params.UniqueCount,
		DependencyCount:   int64(params.DepCount),
		Vulnerabilities:   vulnReport.Vulnerabilities,
		Ok:                len(params.Findings) == 0,
		Filtered: definitions.Filtered{
			Ignore: vulnReport.Ignored,
			Patch:  make([]string, 0),
		},
	}
	totalVulnCount := len(vulnReport.Ignored) + len(vulnReport.Vulnerabilities)
	switch totalVulnCount {
	case 0:
		res.Summary = "No known vulnerabilities"
	case 1:
		res.Summary = "1 vulnerable dependency path"
	default:
		res.Summary = fmt.Sprintf("%d vulnerable dependency paths", totalVulnCount)
	}

	remSummary, err := RemediationSummaryToLegacy(res.Vulnerabilities, params.RemediationSummary)
	if err != nil {
		return nil, params.ErrFactory.NewLegacyJSONTransformerError(fmt.Errorf("failed to compute remediation summary: %w", err))
	}
	res.Remediation = remSummary

	policy, err := cmdutil.GetLocalPolicy(ctx, params.TargetDir)
	if err != nil {
		return nil, params.ErrFactory.NewLegacyJSONTransformerError(fmt.Errorf("failed to get local policy: %w", err))
	}

	if policy != nil {
		res.FilesystemPolicy = true
	}

	policyStr, err := ExtendLocalPolicyFromFindings(ctx, policy, params.Findings)
	if err != nil {
		return nil, params.ErrFactory.NewLegacyJSONTransformerError(fmt.Errorf("failed to convert to local policy: %w", err))
	}
	res.Policy = policyStr

	return &res, nil
}

// FindingsToLegacyVulns converts a slice of snyk schema findings into a slice of legacy vulnerabilities.
func FindingsToLegacyVulns(
	findings []testapi.FindingData,
	packageManager string,
	logger *zerolog.Logger,
) ([]definitions.Vulnerability, error) {
	vulns := []definitions.Vulnerability{}
	for _, finding := range findings {
		findingVulns, err := FindingToLegacyVulns(&finding, logger)
		if err != nil {
			return nil, err
		}

		for i := range findingVulns {
			vuln := findingVulns[i]
			ensurePackageManager(&vuln, packageManager)
			vulns = append(vulns, vuln)
		}
	}
	return vulns, nil
}

// FindingToLegacyVulns is the beginning of the workflow in converting a snyk schema finding into
// a legacy vulnerability to provide legacy json outputs.
func FindingToLegacyVulns(
	finding *testapi.FindingData,
	logger *zerolog.Logger,
) ([]definitions.Vulnerability, error) {
	baseVuln := definitions.Vulnerability{
		Title:                finding.Attributes.Title,
		Description:          finding.Attributes.Description,
		Severity:             definitions.VulnerabilitySeverity(finding.Attributes.Rating.Severity),
		SeverityWithCritical: utils.Ptr(definitions.VulnerabilitySeverity(finding.Attributes.Rating.Severity)),
	}
	err := processProblemsForVuln(&baseVuln, finding.Attributes.Problems, logger)
	if err != nil {
		return nil, fmt.Errorf("handling problem for finding: %w", err)
	}

	err = processLocationsForVuln(&baseVuln, finding.Attributes.Locations, logger)
	if err != nil {
		return nil, fmt.Errorf("processing location for finding: %w", err)
	}

	processRiskForVuln(&baseVuln, finding.Attributes.Risk)

	ProcessPoliciesAndSuppressionsForVuln(&baseVuln, finding, logger)

	return processEvidencesAndRemediation(finding, &baseVuln, logger)
}

func processProblemsForVuln(baseVuln *definitions.Vulnerability, problems []testapi.Problem, logger *zerolog.Logger) error {
	for i := range problems {
		problem := problems[i]
		err := ProcessProblemForVuln(baseVuln, &problem, logger)
		if err != nil {
			return err
		}
	}
	return nil
}

// ProcessProblemForVuln is responsible for decorating the vulnerability with information provided
// by the problems in the finding.
func ProcessProblemForVuln(
	vuln *definitions.Vulnerability,
	prob *testapi.Problem,
	logger *zerolog.Logger,
) error {
	disc, err := prob.Discriminator()
	if err != nil {
		return fmt.Errorf("getting problem discriminator: %w", err)
	}

	switch disc {
	case string(testapi.SnykVuln):
		return processSnykVulnProblem(vuln, prob, logger)
	case string(testapi.Cve):
		return processCveProblem(vuln, prob)
	case string(testapi.Cwe):
		return processCweProblem(vuln, prob)
	case string(testapi.Ghsa):
		return processGhsaProblem(vuln, prob)
	case string(testapi.SnykLicense):
		return processSnykLicenseProblem(vuln, prob, logger)
	default:
		logger.Warn().Str(logFieldDiscriminator, disc).Msg("unsupported problem type")
	}
	return nil
}

func processSnykVulnProblem(vuln *definitions.Vulnerability, prob *testapi.Problem, logger *zerolog.Logger) error {
	snykProblemVuln, err := prob.AsSnykVulnProblem()
	if err != nil {
		return fmt.Errorf("converting problem to snyk vuln problem: %w", err)
	}
	setBasicVulnInfo(vuln, &snykProblemVuln)
	setVulnReferences(vuln, snykProblemVuln.References)
	setVulnSemver(vuln, &snykProblemVuln)
	setEcosystem(vuln, &snykProblemVuln.Ecosystem, logger)
	setVulnCvssInfo(vuln, &snykProblemVuln)
	setVulnExploitDetails(vuln, &snykProblemVuln.ExploitDetails)
	setVulnEpssDetails(vuln, snykProblemVuln.EpssDetails)
	return nil
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

func setEcosystem(vuln *definitions.Vulnerability, ecosystem *testapi.SnykvulndbPackageEcosystem, logger *zerolog.Logger) {
	ecoDisc, err := ecosystem.Discriminator()
	if err != nil {
		logger.Warn().Err(err).Msg("could not get ecosystem discriminator")
		return
	}
	switch ecoDisc {
	case string(testapi.Build):
		if eco, err := ecosystem.AsSnykvulndbBuildPackageEcosystem(); err == nil {
			vuln.Language = &eco.Language
			vuln.PackageManager = &eco.PackageManager
		} else {
			logger.Warn().Err(err).Msg("could not convert ecosystem to SnykvulndbBuildPackageEcosystem")
		}
	case string(testapi.Os):
		if eco, err := ecosystem.AsSnykvulndbOsPackageEcosystem(); err == nil {
			vuln.PackageManager = util.Ptr(fmt.Sprintf("%s:%s", eco.Distribution, eco.Release))
		} else {
			logger.Warn().Err(err).Msg("could not convert ecosystem to SnykvulndbOsPackageEcosystem")
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
	cvssDetails := make([]definitions.CVSSDetail, 0, len(snykCvssSources))
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
	if len(snykExploitDetails.Sources) == 0 && len(snykExploitDetails.MaturityLevels) == 0 {
		return
	}

	details := &definitions.ExploitDetails{
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
		details.MaturityLevels = maturityLevels
	}
	vuln.ExploitDetails = details
}

func setVulnEpssDetails(vuln *definitions.Vulnerability, snykEpssDetails *testapi.SnykvulndbEpssDetails) {
	if snykEpssDetails == nil {
		return
	}

	vuln.EpssDetails = &definitions.EPSSDetails{
		ModelVersion: util.Ptr(snykEpssDetails.ModelVersion),
		Percentile:   util.Ptr(snykEpssDetails.Percentile),
		Probability:  util.Ptr(snykEpssDetails.Probability),
	}
}

func processLocationsForVuln(vuln *definitions.Vulnerability, locations []testapi.FindingLocation, logger *zerolog.Logger) error {
	for i := range locations {
		location := locations[i]
		err := ProcessLocationForVuln(vuln, &location, logger)
		if err != nil {
			return err
		}
	}
	return nil
}

// ProcessLocationForVuln is responsible for decorating the legacy vulnerability
// with information from the finding's location data.
func ProcessLocationForVuln(
	vuln *definitions.Vulnerability,
	loc *testapi.FindingLocation,
	logger *zerolog.Logger,
) error {
	locDisc, err := loc.Discriminator()
	if err != nil {
		return fmt.Errorf("getting location discriminator: %w", err)
	}
	switch locDisc {
	case string(testapi.Source):
		logger.Warn().Str(logFieldDiscriminator, locDisc).Msg("source location type not yet supported for legacy conversion")
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
		logger.Warn().Str(logFieldDiscriminator, locDisc).Msg("other location type not yet supported for legacy conversion")
		_, err = loc.AsOtherLocation()
		if err != nil {
			return fmt.Errorf("converting location to other location: %w", err)
		}
	default:
		logger.Warn().Str(logFieldDiscriminator, locDisc).Msg("unsupported location type")
	}
	return nil
}

// ProcessEvidenceForFinding extracts the dependency lineage for the vulnerability
// from the evidence provided in the finding and returns an ordered list.
func ProcessEvidenceForFinding(vuln *definitions.Vulnerability, ev *testapi.Evidence) error {
	evDisc, err := ev.Discriminator()
	if err != nil {
		return fmt.Errorf("getting evidence discriminator: %w", err)
	}

	switch evDisc {
	case string(testapi.DependencyPath):
		depPathEvidence, err := ev.AsDependencyPathEvidence()
		if err != nil {
			return fmt.Errorf("converting evidence to dependency path evidence: %w", err)
		}
		from := make([]string, 0, len(depPathEvidence.Path))
		for _, dep := range depPathEvidence.Path {
			from = append(from, fmt.Sprintf("%s@%s", dep.Name, dep.Version))
		}
		vuln.From = from
	case string(testapi.Reachability):
		reachEvidence, err := ev.AsReachabilityEvidence()
		if err != nil {
			return fmt.Errorf("converting evidence to reachability evidence: %w", err)
		}
		switch reachEvidence.Reachability {
		case testapi.ReachabilityTypeFunction:
			vuln.Reachability = util.Ptr(definitions.Reachable)
		case testapi.ReachabilityTypeNoInfo:
			vuln.Reachability = util.Ptr(definitions.NoPathFound)
		case testapi.ReachabilityTypeNotApplicable:
			vuln.Reachability = util.Ptr(definitions.NotApplicable)
		default:
			// No reachability value set for these types
		}
	}
	return nil
}

func processEvidencesAndRemediation(
	finding *testapi.FindingData,
	baseVuln *definitions.Vulnerability,
	logger *zerolog.Logger,
) ([]definitions.Vulnerability, error) {
	var depPathEvidences []testapi.Evidence
	var otherEvidences []testapi.Evidence
	for _, ev := range finding.Attributes.Evidence {
		evDisc, err := ev.Discriminator()
		if err != nil {
			return nil, fmt.Errorf("getting evidence discriminator: %w", err)
		}
		if evDisc == string(testapi.DependencyPath) {
			depPathEvidences = append(depPathEvidences, ev)
		} else {
			otherEvidences = append(otherEvidences, ev)
		}
	}

	var vulnCount int
	if len(depPathEvidences) > 0 {
		vulnCount = len(depPathEvidences)
	} else {
		vulnCount = 1
	}
	vulns := make([]definitions.Vulnerability, 0, vulnCount)

	// Create a new legacy vulnerability for each dependency path evidence.
	for _, depPathEv := range depPathEvidences {
		vuln := *baseVuln
		vuln.From = []string{}
		err := ProcessEvidenceForFinding(&vuln, &depPathEv)
		if err != nil {
			return nil, fmt.Errorf(errProcessEvidenceForFindingStr, err)
		}

		if err := processOtherEvidence(&vuln, otherEvidences); err != nil {
			return nil, err
		}

		if err := ProcessRemediationForFinding(&vuln, finding, logger); err != nil {
			return nil, err
		}
		vulns = append(vulns, vuln)
	}

	// If no dependency path evidence exists for fining.
	// Create a vuln with an empty "from", but process the other evidence.
	if len(depPathEvidences) == 0 {
		vuln := *baseVuln
		vuln.From = []string{}

		if err := processOtherEvidence(&vuln, otherEvidences); err != nil {
			return nil, err
		}

		if err := ProcessRemediationForFinding(&vuln, finding, logger); err != nil {
			return nil, err
		}
		vulns = append(vulns, vuln)
	}

	return vulns, nil
}

func processOtherEvidence(vuln *definitions.Vulnerability, otherEvidences []testapi.Evidence) error {
	for _, otherEv := range otherEvidences {
		err := ProcessEvidenceForFinding(vuln, &otherEv)
		if err != nil {
			return fmt.Errorf(errProcessEvidenceForFindingStr, err)
		}
	}
	return nil
}

func ensurePackageManager(vuln *definitions.Vulnerability, defaultPackageManager string) {
	if vuln.PackageManager == nil {
		vuln.PackageManager = &defaultPackageManager
	}
}

func processRiskForVuln(vuln *definitions.Vulnerability, risk testapi.Risk) {
	if risk.RiskScore != nil {
		vuln.RiskScore = &risk.RiskScore.Value
	}
}

// processCveProblem processes a CVE problem by extracting its identifier and adding it to the vulnerability.
func processCveProblem(v *definitions.Vulnerability, prob *testapi.Problem) error {
	ensureVulnHasIdentifiers(v)
	cve, err := prob.AsCveProblem()
	if err != nil {
		return fmt.Errorf("converting problem to cve: %w", err)
	}
	v.Identifiers.CVE = append(v.Identifiers.CVE, cve.Id)
	return nil
}

// processCweProblem processes a CWE problem by extracting its identifier and adding it to the vulnerability.
func processCweProblem(v *definitions.Vulnerability, prob *testapi.Problem) error {
	ensureVulnHasIdentifiers(v)
	cwe, err := prob.AsCweProblem()
	if err != nil {
		return fmt.Errorf("converting problem to cwe: %w", err)
	}
	v.Identifiers.CWE = append(v.Identifiers.CWE, cwe.Id)
	return nil
}

func processGhsaProblem(v *definitions.Vulnerability, prob *testapi.Problem) error {
	ensureVulnHasIdentifiers(v)
	ghsa, err := prob.AsGithubSecurityAdvisoryProblem()
	if err != nil {
		return fmt.Errorf("converting problem to github security advisory: %w", err)
	}
	if v.Identifiers.GHSA == nil {
		v.Identifiers.GHSA = &[]string{}
	}
	*v.Identifiers.GHSA = append(*v.Identifiers.GHSA, ghsa.Id)
	return nil
}

// processSnykLicenseProblem processes a Snyk license problem by extracting its data and populating the vulnerability.
func processSnykLicenseProblem(v *definitions.Vulnerability, prob *testapi.Problem, logger *zerolog.Logger) error {
	license, err := prob.AsSnykLicenseProblem()
	if err != nil {
		return fmt.Errorf("converting problem to snyk license: %w", err)
	}
	setBasicLicenseInfo(v, &license)
	setEcosystem(v, &license.Ecosystem, logger)
	setLicenseSemver(v, &license)
	return nil
}

// setBasicLicenseInfo sets basic license information from a Snyk license problem.
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

	if instructions := convertLicenseInstructions(license.Instructions); len(instructions) > 0 {
		v.LegalInstructionsArray = &instructions
	}
}

// convertLicenseInstructions converts license instructions to the json format.
func convertLicenseInstructions(instructionsList []testapi.SnykvulndbLicenseInstructions) []definitions.LegalInstruction {
	if len(instructionsList) == 0 {
		return nil
	}

	instructions := make([]definitions.LegalInstruction, 0, len(instructionsList))
	for _, inst := range instructionsList {
		if inst.Content == "" {
			continue
		}
		instructions = append(instructions, definitions.LegalInstruction{
			LicenseName:  inst.License,
			LegalContent: inst.Content,
		})
	}

	if len(instructions) == 0 {
		return nil
	}
	return instructions
}

// ensureVulnHasIdentifiers ensures that a vulnerability has an identifiers field initialized.
func ensureVulnHasIdentifiers(v *definitions.Vulnerability) {
	if v.Identifiers == nil {
		v.Identifiers = &definitions.Identifiers{CVE: []string{}, CWE: []string{}}
	}
}
