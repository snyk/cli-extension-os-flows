package transform_test

import (
	_ "embed"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/legacy/transform"
	"github.com/snyk/cli-extension-os-flows/internal/util"
	"github.com/snyk/cli-extension-os-flows/pkg/localpolicy"
)

//go:embed testdata/finding-with-suppression-stub.json
var findingWithSuppression []byte

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

func TestExtendLocalPolicyFromSchema(t *testing.T) {
	fixedPolicy := `version: v1.2.0
ignore:
    SNYK-JS-EXPRESS-6474509:
        - goof@1.0.0 > express@1.2.3:
            expires: 2025-06-03T07:41:24Z
            reason: none given
patch: {}
`
	expectedPolicy := `version: v1.2.0
ignore:
    SNYK-JS-EXPRESS-6474509:
        - goof@1.0.0 > express@1.2.3:
            expires: 2025-06-03T07:41:24Z
            reason: none given
    SNYK-JS-TARFS-10293725:
        - '*':
            created: 2025-06-03T07:41:24Z
            expires: 2025-06-03T07:41:24Z
            ignoredBy:
                email: janedoe@example.com
                name: Jane Doe
                id: 082c9473-b58c-4936-bf44-46131e3ffdb9
            reason: This is a test suppression
            reasonType: wont-fix
            source: api
patch: {}
`
	// create temporary .snyk file
	tmpDotSnyk, err := os.CreateTemp("", ".snyk")
	require.NoError(t, err)
	t.Cleanup(func() { os.Remove(tmpDotSnyk.Name()) })
	_, err = tmpDotSnyk.WriteString(fixedPolicy)
	require.NoError(t, err)
	lp, err := localpolicy.Load(tmpDotSnyk.Name())
	require.NoError(t, err)

	// load fixed findings
	var findings testapi.FindingData
	err = json.Unmarshal(findingWithSuppression, &findings)
	require.NoError(t, err)

	policy, err := transform.ExtendLocalPolicyFromSchema(lp, []testapi.FindingData{findings})
	require.NoError(t, err)

	assert.Equal(t, expectedPolicy, policy)
}

func timeMustParse(t *testing.T, val string) *time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339Nano, val)
	require.NoError(t, err)
	return &parsed
}
