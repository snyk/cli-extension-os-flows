package remediation

import "iter"

// Input.

// Finding represents a vulnerability for a given package & version.
// If a finding is introduced through multiple paths, a single finding with several `DependencyPath` entries must be constructed.
type Finding struct {
	Package         Package
	Vulnerability   Vulnerability
	DependencyPaths []DependencyPath

	// All versions containing a fix for this problem
	FixedInVersions []string
	Fix             Fix
	PackageManager  PackageManager
	Ignored         bool
}

// Findings represents a collection of vulnerability findings.
type Findings []*Finding

// WithPinFixes returns an iterator over findings that have pin fixes.
func (f Findings) WithPinFixes() iter.Seq2[*Finding, PinFix] {
	return func(yield func(*Finding, PinFix) bool) {
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

// WithUpgradeFixes returns an iterator over findings that have upgrade fixes.
func (f Findings) WithUpgradeFixes() iter.Seq2[*Finding, UpgradeFix] {
	return func(yield func(*Finding, UpgradeFix) bool) {
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

// WithUnresolvedFixes returns an iterator over findings that have unresolved fixes.
func (f Findings) WithUnresolvedFixes() iter.Seq2[*Finding, UnresolvedFix] {
	return func(yield func(*Finding, UnresolvedFix) bool) {
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

// PackageManager represents the type of package manager used.
type PackageManager string

// Outcome represents the result of a remediation action.
type Outcome string

// Fix represents a remediation action that can be taken to address a vulnerability.
type Fix interface {
	Outcome() Outcome
}

// PinFix represents a fix that pins a package to a specific version.
type PinFix struct {
	outcome   Outcome
	PinAction PinAction
}

// PinAction represents the action of pinning a package.
type PinAction struct {
	Package Package
}

// Outcome returns the outcome of the pin fix.
func (pf PinFix) Outcome() Outcome {
	return pf.outcome
}

// NewPinFix creates a new pin fix with the given outcome and action.
func NewPinFix(outcome Outcome, action PinAction) Fix {
	return PinFix{
		outcome:   outcome,
		PinAction: action,
	}
}

// UpgradeFix represents a fix that upgrades a package to a newer version.
type UpgradeFix struct {
	outcome       Outcome
	UpgradeAction UpgradeAction
}

// UpgradeAction represents the action of upgrading a package.
type UpgradeAction struct {
	PackageName  string
	UpgradePaths []DependencyPath
}

// Outcome returns the outcome of the upgrade fix.
func (uf UpgradeFix) Outcome() Outcome {
	return uf.outcome
}

// NewUpgradeFix creates a new upgrade fix with the given outcome and action.
func NewUpgradeFix(outcome Outcome, action UpgradeAction) Fix {
	return UpgradeFix{
		outcome:       outcome,
		UpgradeAction: action,
	}
}

// UnresolvedFix represents a fix that cannot be resolved.
type UnresolvedFix struct{}

// Outcome returns the unresolved outcome.
func (uf UnresolvedFix) Outcome() Outcome {
	return Unresolved
}

// VulnID represents a vulnerability identifier.
type VulnID string

// NewUnresolvedFix creates a new unresolved fix.
func NewUnresolvedFix() Fix {
	return UnresolvedFix{}
}

// Fix outcomes.
const (
	FullyResolved     Outcome = "fully_resolved"
	PartiallyResolved Outcome = "partially_resolved"
	Unresolved        Outcome = "unresolved"
)

// Output.

// Summary is the root aggregate that contains remediation advice to tackle vulnerabilities optimally.
type Summary struct {
	/**
	Pins model transitive upgrades that for whatever reason cannot be addressed
	by performing direct upgrades in the first package of the dependency path.

	In pins, the upgraded package is always the vulnerable one
	*/
	Pins []*Upgrade
	/**
	Upgrades model direct version bumps to direct dependencies that address a vulnerability
	by eventually bumping the vulnerable package to a patched version

	In upgrades, the upgraded package may not be the vulnerable one, but it will trigger
	a chain reaction that will bump it nevertheless.
	*/
	Upgrades []*Upgrade

	/**
	Unresolved models all vulns that do not have a resolution known to Snyk. Either because
	there is no known fix for the vulnerable package, or because there's no viable upgrade
	through direct dependencies to bump it.
	*/
	Unresolved []*VulnerabilityInPackage
}

// Upgrade represents a package upgrade from one version to another.
type Upgrade struct {
	From Package
	To   Package

	Fixes []*VulnerabilityInPackage
}

// VulnerabilityInPackage represents a vulnerability found in a specific package.
type VulnerabilityInPackage struct {
	VulnerablePackage Package
	Vulnerability     Vulnerability
	FixedInVersions   []string
	IntroducedThrough []DependencyPath
}

// DependencyPath represents a path of dependencies.
type DependencyPath = []Package

// Package represents a software package with its name and version.
type Package struct {
	Name    string
	Version string
}

// Vulnerability represents a security vulnerability.
type Vulnerability struct {
	ID       VulnID
	Name     string
	Severity Severity
}

// Severity represents the severity level of a vulnerability.
type Severity string

// Severity levels.
const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityNone     Severity = "none"
	SeverityOther    Severity = "other"
)
