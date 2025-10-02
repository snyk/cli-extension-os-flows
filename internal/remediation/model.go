package remediation

import "iter"

// Input

/**
* Finding represents a vulnerability for a given package & version.
*
* If a finding is introduced through multiple paths, a single finding with several `DependencyPath` entries must be constructed.
 */
type Finding struct {
	Package         Package
	Vulnerability   Vulnerability
	DependencyPaths []DependencyPath

	// All versions containing a fix for this problem
	FixedInVersions []string
	Fix             Fix
	PackageManager  PackageManager
}

type Findings []Finding

func (f Findings) WithPinFixes() iter.Seq2[Finding, PinFix] {
	return func(yield func(Finding, PinFix) bool) {
		for _, finding := range f {
			switch fix := finding.Fix.(type) {
			case PinFix:
				if !yield(finding, fix) {
					return
				}
			default:
				continue
			}
		}
	}
}

func (f Findings) WithUpgradeFixes() iter.Seq2[Finding, UpgradeFix] {
	return func(yield func(Finding, UpgradeFix) bool) {
		for _, finding := range f {
			switch fix := finding.Fix.(type) {
			case UpgradeFix:
				if !yield(finding, fix) {
					return
				}
			default:
				continue
			}
		}
	}
}

func (f Findings) WithUnresolvedFixes() iter.Seq2[Finding, UnresolvedFix] {
	return func(yield func(Finding, UnresolvedFix) bool) {
		for _, finding := range f {
			switch fix := finding.Fix.(type) {
			case UnresolvedFix:
				if !yield(finding, fix) {
					return
				}
			default:
				continue
			}
		}
	}
}

type PackageManager string

type Outcome string
type Fix interface {
	Outcome() Outcome
}

type PinFix struct {
	outcome   Outcome
	PinAction PinAction
}

type PinAction struct {
	Package Package
}

func (pf PinFix) Outcome() Outcome {
	return pf.outcome
}

func NewPinFix(outcome Outcome, action PinAction) Fix {
	return PinFix{
		outcome:   outcome,
		PinAction: action,
	}
}

type UpgradeFix struct {
	outcome       Outcome
	UpgradeAction UpgradeAction
}
type UpgradeAction struct {
	PackageName  string
	UpgradePaths []DependencyPath
}

func (uf UpgradeFix) Outcome() Outcome {
	return uf.outcome
}

func NewUpgradeFix(outcome Outcome, action UpgradeAction) Fix {
	return UpgradeFix{
		outcome:       outcome,
		UpgradeAction: action,
	}
}

type UnresolvedFix struct{}

func (uf UnresolvedFix) Outcome() Outcome {
	return Unresolved
}

type VulnID string

func NewUnresolvedFix() Fix {
	return UnresolvedFix{}
}

const (
	FullyResolved     Outcome = "fully-resolved"
	PartiallyResolved Outcome = "partially-resolved"
	Unresolved        Outcome = "unresolved"
)

// Output

/*
*
A remediation summary is the root aggregate that contains remediation advice to tackle vulnerabilities optimally
*/
type Summary struct {
	/**
	Pins model transitive upgrades that for whatever reason cannot be addressed
	by performing direct upgrades in the first package of the dependency path.

	In pins, the upgraded package is always the vulnerable one
	*/
	Pins []Upgrade
	/**
	Upgrades model direct version bumps to direct dependencies that address a vulnerability
	by eventually bumping the vulnerable package to a patched version

	In upgrades, the upgraded package may not be the vulnerable one, but it will trigger
	a chain reaction that will bump it nevertheless.
	*/
	Upgrades []Upgrade

	/**
	Unresolved models all vulns that do not have a resolution known to Snyk. Either because
	there is no known fix for the vulnerable package, or because there's no viable upgrade
	through direct dependencies to bump it.
	*/
	Unresolved []VulnerabilityInPackage
}

type Upgrade struct {
	From Package
	To   Package

	Fixes []VulnerabilityInPackage
}

type VulnerabilityInPackage struct {
	VulnerablePackage Package
	Vulnerability     Vulnerability
	FixedInVersions   []string
	IntroducedThrough []DependencyPath
}

type DependencyPath = []Package
type Package struct {
	Name    string
	Version string
}

type Vulnerability struct {
	ID       VulnID
	Name     string
	Severity Severity
}

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityNone     Severity = "none"
	SeverityOther    Severity = "other"
)
