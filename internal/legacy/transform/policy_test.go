package transform_test

import (
	"testing"
	"time"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/legacy/transform"
	"github.com/snyk/cli-extension-os-flows/internal/util"
	"github.com/snyk/cli-extension-os-flows/pkg/localpolicy"
)

func TestLegacyPolicyToLocalIgnores(t *testing.T) {
	p := &localpolicy.Policy{
		Version: "v1.0.0",
		Ignore: localpolicy.RuleSet{
			"npm:hawk:20160119": []localpolicy.RuleEntry{
				{
					"sqlite > sqlite3 > node-pre-gyp > request > hawk": &localpolicy.Rule{
						Reason:  util.Ptr("hawk got bumped"),
						Expires: timeMustParse(t, "2116-03-01T14:30:04.136Z"),
					},
				},
			},
			"npm:method-override:20170927": []localpolicy.RuleEntry{
				{
					"*": &localpolicy.Rule{
						Reason:  util.Ptr("none given"),
						Created: timeMustParse(t, "2022-04-10T15:56:02.074Z"),
					},
				},
			},
		},
	}

	result := transform.LocalPolicyToSchema(p)

	require.NotNil(t, result)
	require.Len(t, *result, 2)

	// Convert to map for order-independent lookup
	byVulnID := make(map[string]testapi.LocalIgnore)
	for _, ignore := range *result {
		byVulnID[ignore.VulnId] = ignore
	}

	// Assert hawk entry
	hawkIgnore := byVulnID["npm:hawk:20160119"]
	assert.Equal(t, "npm:hawk:20160119", hawkIgnore.VulnId)
	assert.Equal(t, "hawk got bumped", *hawkIgnore.Reason)
	require.NotNil(t, hawkIgnore.Path)
	assert.Equal(t, []string{"sqlite", "sqlite3", "node-pre-gyp", "request", "hawk"}, *hawkIgnore.Path)
	assert.Equal(t, timeMustParse(t, "2116-03-01T14:30:04.136Z"), hawkIgnore.ExpiresAt)
	assert.Nil(t, hawkIgnore.CreatedAt)

	// Assert method-override entry
	methodIgnore := byVulnID["npm:method-override:20170927"]
	assert.Equal(t, "npm:method-override:20170927", methodIgnore.VulnId)
	assert.Equal(t, "none given", *methodIgnore.Reason)
	assert.Nil(t, methodIgnore.Path)
	assert.Equal(t, timeMustParse(t, "2022-04-10T15:56:02.074Z"), methodIgnore.CreatedAt)
	assert.Nil(t, methodIgnore.ExpiresAt)
}

func TestLegacyPolicyToLocalIgnores_NoIgnores(t *testing.T) {
	p := &localpolicy.Policy{
		Version: "v1.0.0",
		Ignore:  localpolicy.RuleSet{},
	}
	lp := transform.LocalPolicyToSchema(p)

	assert.Nil(t, lp)
}

func timeMustParse(t *testing.T, val string) *time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339Nano, val)
	require.NoError(t, err)
	return &parsed
}
