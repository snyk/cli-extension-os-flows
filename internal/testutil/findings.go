package testutil

import (
	"testing"

	"github.com/google/uuid"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/util"
)

type fixData = struct {
	Attributes *testapi.FixAttributes `json:"attributes,omitempty"`
	Id         uuid.UUID              `json:"id"` //nolint:revive // matches testapi structure
	Type       string                 `json:"type"`
}

type relationshipFix = struct {
	Data *fixData `json:"data,omitempty"`
}

type findingRelationship = struct {
	Asset *struct {
		Data *struct {
			Id   uuid.UUID `json:"id"` //nolint:revive // matches testapi structure
			Type string    `json:"type"`
		} `json:"data,omitempty"`
		Links testapi.IoSnykApiCommonRelatedLink `json:"links"`
		Meta  *testapi.IoSnykApiCommonMeta       `json:"meta,omitempty"`
	} `json:"asset,omitempty"`
	Fix *relationshipFix `json:"fix,omitempty"`
	Org *struct {
		Data *struct {
			Id   uuid.UUID `json:"id"` //nolint:revive // matches testapi structure
			Type string    `json:"type"`
		} `json:"data,omitempty"`
	} `json:"org,omitempty"`
	Policy *struct {
		Data *struct {
			Attributes *testapi.PolicyAttributes `json:"attributes,omitempty"`
			Id         uuid.UUID                 `json:"id"` //nolint:revive // matches testapi structure
			Type       string                    `json:"type"`
		} `json:"data,omitempty"`
		Links testapi.IoSnykApiCommonRelatedLink `json:"links"`
		Meta  *testapi.IoSnykApiCommonMeta       `json:"meta,omitempty"`
	} `json:"policy,omitempty"`
	Test *struct {
		Data *struct {
			Id   uuid.UUID `json:"id"` //nolint:revive // matches testapi structure
			Type string    `json:"type"`
		} `json:"data,omitempty"`
		Links testapi.IoSnykApiCommonRelatedLink `json:"links"`
		Meta  *testapi.IoSnykApiCommonMeta       `json:"meta,omitempty"`
	} `json:"test,omitempty"`
}

type findingBuilder struct {
	t           *testing.T
	title       string
	vulnID      string
	severity    testapi.Severity
	suppression *testapi.Suppression
	fix         *testapi.Action
}

// FindingOption is a functional option for configuring test findings.
type FindingOption func(*findingBuilder)

// WithTitle sets the title of the test finding.
func WithTitle(title string) FindingOption {
	return func(b *findingBuilder) { b.title = title }
}

// WithVulnID sets the vulnerability ID of the test finding.
func WithVulnID(vulnID string) FindingOption {
	return func(b *findingBuilder) { b.vulnID = vulnID }
}

// WithSeverity sets the severity of the test finding.
func WithSeverity(severity testapi.Severity) FindingOption {
	return func(b *findingBuilder) { b.severity = severity }
}

// WithSuppression sets the suppression status of the test finding.
func WithSuppression(suppression *testapi.Suppression) FindingOption {
	return func(b *findingBuilder) { b.suppression = suppression }
}

// WithUpgradeFix adds an upgrade fix to the test finding.
func WithUpgradeFix(pkgName, version string) FindingOption {
	return func(b *findingBuilder) {
		act := testapi.Action{}
		require.NoError(b.t, act.FromUpgradePackageAction(testapi.UpgradePackageAction{
			PackageName:  pkgName,
			UpgradePaths: []testapi.UpgradePath{{DependencyPath: []testapi.Package{{Name: pkgName, Version: version}}}},
			Type:         testapi.UpgradePackage,
		}))
		b.fix = &act
	}
}

// NewFinding creates a test finding with the given options.
func NewFinding(t *testing.T, opts ...FindingOption) testapi.FindingData {
	t.Helper()

	b := &findingBuilder{
		t:        t,
		title:    "Test Vulnerability",
		vulnID:   "SNYK-JS-ACORN-001",
		severity: testapi.SeverityHigh,
	}

	for _, opt := range opts {
		opt(b)
	}

	loc := testapi.FindingLocation{}
	require.NoError(t, loc.FromPackageLocation(testapi.PackageLocation{
		Package: testapi.Package{Name: "acorn", Version: "5.7.1"},
		Type:    testapi.PackageLocationTypePackage,
	}))

	ev := testapi.Evidence{}
	require.NoError(t, ev.FromDependencyPathEvidence(testapi.DependencyPathEvidence{
		Path:   []testapi.Package{{Name: "root", Version: "1.0.0"}, {Name: "acorn", Version: "5.7.1"}},
		Source: testapi.DependencyPath,
	}))

	ecosystem := testapi.SnykvulndbPackageEcosystem{}
	require.NoError(t, ecosystem.FromSnykvulndbBuildPackageEcosystem(testapi.SnykvulndbBuildPackageEcosystem{
		Language: "js", PackageManager: "npm", Type: testapi.Build,
	}))

	prob := testapi.Problem{}
	require.NoError(t, prob.FromSnykVulnProblem(testapi.SnykVulnProblem{
		Id: b.vulnID, Ecosystem: ecosystem, InitiallyFixedInVersions: []string{"5.7.4"},
	}))

	finding := testapi.FindingData{
		Id:   util.Ptr(uuid.New()),
		Type: util.Ptr(testapi.Findings),
		Attributes: &testapi.FindingAttributes{
			Title:       b.title,
			Rating:      testapi.Rating{Severity: b.severity},
			Evidence:    []testapi.Evidence{ev},
			Locations:   []testapi.FindingLocation{loc},
			Problems:    []testapi.Problem{prob},
			Suppression: b.suppression,
		},
	}

	if b.fix != nil {
		finding.Relationships = &findingRelationship{
			Fix: &relationshipFix{
				Data: &fixData{
					Attributes: &testapi.FixAttributes{Outcome: testapi.FullyResolved, Actions: b.fix},
				},
			},
		}
	}

	return finding
}
