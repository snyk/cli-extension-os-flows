package transform_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/oapi-codegen/runtime/types"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/legacy/definitions"
	"github.com/snyk/cli-extension-os-flows/internal/legacy/transform"
	"github.com/snyk/cli-extension-os-flows/internal/semver"
	"github.com/snyk/cli-extension-os-flows/internal/util"
)

func Test_CalculatePins(t *testing.T) {
	pinAction := testapi.PinPackageAction{
		PackageName: "pylint",
		PinVersion:  "2.7.0",
		Type:        testapi.PinPackage,
	}
	act := testapi.Action{}
	act.FromPinPackageAction(pinAction)

	dpe := testapi.DependencyPathEvidence{
		Path: []testapi.Package{
			{
				Name:    "snyk-fix-pyenv",
				Version: "0.0.0",
			},
			{
				Name:    "pylint",
				Version: "2.6.0",
			},
		},
	}
	ev := testapi.Evidence{}
	ev.FromDependencyPathEvidence(dpe)

	svp := testapi.SnykVulnProblem{
		PackageName:    "pylint",
		PackageVersion: "",
	}

	findings := []testapi.FindingData{
		{
			Id: util.Ptr(uuid.New()),
			Attributes: &testapi.FindingAttributes{
				Evidence: []testapi.Evidence{ev},
				Problems: []testapi.Problem{},
			},
			Relationships: &struct {
				Asset *struct {
					Data *struct {
						Id   types.UUID "json:\"id\""
						Type string     "json:\"type\""
					} "json:\"data,omitempty\""
					Links testapi.IoSnykApiCommonRelatedLink "json:\"links\""
					Meta  *testapi.IoSnykApiCommonMeta       "json:\"meta,omitempty\""
				} "json:\"asset,omitempty\""
				Fix *struct {
					Data *struct {
						Attributes *testapi.FixAttributes "json:\"attributes,omitempty\""
						Id         types.UUID             "json:\"id\""
						Type       string                 "json:\"type\""
					} "json:\"data,omitempty\""
				} "json:\"fix,omitempty\""
				Org *struct {
					Data *struct {
						Id   types.UUID "json:\"id\""
						Type string     "json:\"type\""
					} "json:\"data,omitempty\""
				} "json:\"org,omitempty\""
				Policy *struct {
					Data *struct {
						Id   types.UUID "json:\"id\""
						Type string     "json:\"type\""
					} "json:\"data,omitempty\""
					Links testapi.IoSnykApiCommonRelatedLink "json:\"links\""
					Meta  *testapi.IoSnykApiCommonMeta       "json:\"meta,omitempty\""
				} "json:\"policy,omitempty\""
				Test *struct {
					Data *struct {
						Id   types.UUID "json:\"id\""
						Type string     "json:\"type\""
					} "json:\"data,omitempty\""
					Links testapi.IoSnykApiCommonRelatedLink "json:\"links\""
					Meta  *testapi.IoSnykApiCommonMeta       "json:\"meta,omitempty\""
				} "json:\"test,omitempty\""
			}{
				Fix: &struct {
					Data *struct {
						Attributes *testapi.FixAttributes "json:\"attributes,omitempty\""
						Id         types.UUID             "json:\"id\""
						Type       string                 "json:\"type\""
					} "json:\"data,omitempty\""
				}{
					Data: &struct {
						Attributes *testapi.FixAttributes "json:\"attributes,omitempty\""
						Id         types.UUID             "json:\"id\""
						Type       string                 "json:\"type\""
					}{
						Attributes: &testapi.FixAttributes{
							Outcome: testapi.FullyResolved,
							Actions: &act,
						},
					},
				},
			},
		},
	}
	smvr, err := semver.GetSemver("pip")
	require.NoError(t, err)

	pins, err := transform.CalculatePins(findings, smvr)
	require.NoError(t, err)

	lintpin, ok := pins["pylint@2.6.0"]
	require.True(t, ok)
	assert.Equal(t, definitions.PinRemediation{
		UpgradeTo:    "pylint@2.7.0",
		IsTransitive: true,
		Vulns:        []string{"SNYK-PYTHON-PYLINT-1089548"},
	}, lintpin)
}
