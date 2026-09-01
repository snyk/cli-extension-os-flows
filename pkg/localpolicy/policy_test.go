package localpolicy_test

import (
	"bytes"
	_ "embed"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/util"
	"github.com/snyk/cli-extension-os-flows/pkg/localpolicy"
)

//go:embed testdata/ignore.yaml
var fixedPolicy []byte

func TestPolicy_New(t *testing.T) {
	p := localpolicy.New()

	assert.NotNil(t, p)
	assert.NotZero(t, p.Version)
	assert.NotNil(t, p.Ignore)
	assert.NotNil(t, p.Patch)
}

func TestPolicy_Unmarshal(t *testing.T) {
	buf := bytes.NewBuffer(fixedPolicy)
	var p localpolicy.Policy

	err := localpolicy.Unmarshal(buf, &p)
	require.NoError(t, err)

	assert.Equal(t, "v1.0.0", p.Version)
	assert.Len(t, p.Ignore, 5)

	ruleSet, ok := p.Ignore["npm:is-my-json-valid:20160118"]
	require.True(t, ok)
	require.Len(t, ruleSet, 1)
}

func TestPolicy_Unmarshal_EmptyCollections(t *testing.T) {
	testCases := map[string]string{
		"empty sequence": `version: v1.25.0
ignore: []
patch: []
`,
		"empty mapping": `version: v1.25.0
ignore: {}
patch: {}
`,
		"legacy TS default (ignore seq, patch map)": `# Snyk (https://snyk.io) policy file, patches or ignores known vulnerabilities.
version: v1.25.0
# ignores vulnerabilities until expiry date; change duration by modifying expiry date
ignore: []
patch: {}
`,
		"null values": `version: v1.25.0
ignore:
patch:
`,
	}

	for name, content := range testCases {
		t.Run(name, func(t *testing.T) {
			var p localpolicy.Policy
			err := localpolicy.Unmarshal(bytes.NewBufferString(content), &p)
			require.NoError(t, err)

			assert.Equal(t, "v1.25.0", p.Version)
			assert.Empty(t, p.Ignore)
			assert.Empty(t, p.Patch)
		})
	}
}

func TestPolicy_Unmarshal_Populated(t *testing.T) {
	content := `# Snyk (https://snyk.io) policy file
version: v1.25.0
ignore:
  'SNYK-JS-LODASH-567746':
    - '*':
        reason: not exploitable in our usage
        reasonType: not-vulnerable
        expires: '2116-03-01T14:30:04.136Z'
        created: '2024-01-15T09:00:00Z'
        source: cli
        ignoredBy:
          id: 00000000-0000-0000-0000-000000000001
          name: Alice
          email: alice@example.com
    - app > lodash:
        reason: pinned via override
        expires: '2030-06-01T00:00:00Z'
        disregardIfFixable: true
  'SNYK-JS-AXIOS-123':
    - '*':
        reason: none given
        disregardIfFixable: false
patch: {}
`

	var p localpolicy.Policy
	err := localpolicy.Unmarshal(bytes.NewBufferString(content), &p)
	require.NoError(t, err)

	assert.Equal(t, "v1.25.0", p.Version)
	assert.Empty(t, p.Patch)
	require.Len(t, p.Ignore, 2)

	lodashEntries, ok := p.Ignore["SNYK-JS-LODASH-567746"]
	require.True(t, ok)
	require.Len(t, lodashEntries, 2)

	wildcardRule, ok := lodashEntries[0]["*"]
	require.True(t, ok, "expected wildcard path in first lodash entry")
	require.NotNil(t, wildcardRule)
	assert.Equal(t, util.Ptr("not exploitable in our usage"), wildcardRule.Reason)
	assert.Equal(t, util.Ptr(localpolicy.ReasonType("not-vulnerable")), wildcardRule.ReasonType)
	assert.Equal(t, util.Ptr("cli"), wildcardRule.Source)
	require.NotNil(t, wildcardRule.Expires)
	assert.Equal(t, time.Date(2116, 3, 1, 14, 30, 4, 136_000_000, time.UTC), wildcardRule.Expires.UTC())
	require.NotNil(t, wildcardRule.Created)
	assert.Equal(t, time.Date(2024, 1, 15, 9, 0, 0, 0, time.UTC), wildcardRule.Created.UTC())
	require.NotNil(t, wildcardRule.IgnoredBy)
	assert.Equal(t, util.Ptr("Alice"), wildcardRule.IgnoredBy.Name)
	assert.Equal(t, util.Ptr("alice@example.com"), wildcardRule.IgnoredBy.Email)
	assert.Equal(t, util.Ptr("00000000-0000-0000-0000-000000000001"), wildcardRule.IgnoredBy.ID)

	pathRule, ok := lodashEntries[1]["app > lodash"]
	require.True(t, ok, "expected explicit path in second lodash entry")
	require.NotNil(t, pathRule)
	assert.Equal(t, util.Ptr("pinned via override"), pathRule.Reason)
	assert.Equal(t, util.Ptr(true), pathRule.DisregardIfFixable)
	require.NotNil(t, pathRule.Expires)
	assert.Equal(t, time.Date(2030, 6, 1, 0, 0, 0, 0, time.UTC), pathRule.Expires.UTC())

	axiosEntries, ok := p.Ignore["SNYK-JS-AXIOS-123"]
	require.True(t, ok)
	require.Len(t, axiosEntries, 1)
	axiosRule, ok := axiosEntries[0]["*"]
	require.True(t, ok)
	require.NotNil(t, axiosRule)
	assert.Equal(t, util.Ptr("none given"), axiosRule.Reason)
	assert.Equal(t, util.Ptr(false), axiosRule.DisregardIfFixable)
	assert.Nil(t, axiosRule.Expires, "axios rule has no expiry")
}

func TestPolicy_Unmarshal_QuotedDateOnlyExpires(t *testing.T) {
	content := `version: v1.25.0
# ignores vulnerabilities until expiry date; change duration by modifying expiry date
ignore:
  SNYK-JS-LODASH-450202:
    - '*':
        reason: None Given
        expires: "2027-08-31"
        created: 2026-08-31T00:00:00.000Z
patch: {}
`

	var p localpolicy.Policy
	err := localpolicy.Unmarshal(bytes.NewBufferString(content), &p)
	require.NoError(t, err)

	entries, ok := p.Ignore["SNYK-JS-LODASH-450202"]
	require.True(t, ok)
	require.Len(t, entries, 1)
	rule, ok := entries[0]["*"]
	require.True(t, ok)
	require.NotNil(t, rule)

	require.NotNil(t, rule.Expires)
	assert.Equal(t, time.Date(2027, 8, 31, 0, 0, 0, 0, time.UTC), rule.Expires.UTC())
	require.NotNil(t, rule.Created)
	assert.Equal(t, time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC), rule.Created.UTC())
}

func TestPolicy_Unmarshal_RejectsNonEmptySequence(t *testing.T) {
	content := `version: v1.25.0
ignore:
  - SNYK-JS-FOO-1
patch: {}
`
	var p localpolicy.Policy
	err := localpolicy.Unmarshal(bytes.NewBufferString(content), &p)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "non-empty sequence")
}

func TestPolicy_Unmarshal_NothingToParse(t *testing.T) {
	testCases := map[string]string{
		"empty file":    ``,
		"whitespace":    "   \n\t\n  \n",
		"comments only": "# nothing to see here\n# really\n",
	}

	for name, content := range testCases {
		t.Run(name, func(t *testing.T) {
			var p localpolicy.Policy
			err := localpolicy.Unmarshal(bytes.NewBufferString(content), &p)
			require.NoError(t, err, "a file with nothing to parse is an absent policy, not a failure")

			assert.Empty(t, p.Version)
			assert.Empty(t, p.Ignore)
			assert.Empty(t, p.Patch)
		})
	}
}

func TestPolicy_Unmarshal_ToleratesNonMappingDocument(t *testing.T) {
	testCases := map[string]string{
		"top-level scalar":   "just a string\n",
		"top-level sequence": "- a\n- b\n",
		"explicit null":      "~\n",
	}

	for name, content := range testCases {
		t.Run(name, func(t *testing.T) {
			var p localpolicy.Policy
			err := localpolicy.Unmarshal(bytes.NewBufferString(content), &p)
			require.NoError(t, err)

			assert.Empty(t, p.Ignore)
		})
	}
}

func TestPolicy_Unmarshal_TabIndentation(t *testing.T) {
	content := "version: v1.25.0\nignore:\n\tSNYK-JS-FOO-1: []\npatch: {}\n"

	var p localpolicy.Policy
	err := localpolicy.Unmarshal(bytes.NewBufferString(content), &p)
	require.NoError(t, err, "legacy accepts a tab-indented policy file")

	assert.Equal(t, "v1.25.0", p.Version)
	_, ok := p.Ignore["SNYK-JS-FOO-1"]
	assert.True(t, ok)
}

func TestPolicy_Unmarshal_MalformedYAMLStillFails(t *testing.T) {
	var p localpolicy.Policy
	err := localpolicy.Unmarshal(bytes.NewBufferString("version: v1.25.0\nignore: [unclosed\n"), &p)
	require.Error(t, err, "tab tolerance must not swallow genuinely malformed YAML")
	assert.Contains(t, err.Error(), "failed to decode snyk policy")
}

func TestPolicy_Unmarshal_NullRuleBody(t *testing.T) {
	content := `version: v1.25.0
ignore:
  SNYK-JS-CXCT-535487:
    - '*':
patch: {}
`

	var p localpolicy.Policy
	err := localpolicy.Unmarshal(bytes.NewBufferString(content), &p)
	require.NoError(t, err)

	entries := p.Ignore["SNYK-JS-CXCT-535487"]
	require.Len(t, entries, 1)
	rule, ok := entries[0]["*"]
	require.True(t, ok)
	require.NotNil(t, rule, "a null rule body must decode to an empty rule, not a nil pointer")
	assert.Nil(t, rule.Reason)
	assert.Nil(t, rule.Expires)
}

func TestPolicy_Unmarshal_UnparseableTimestamp(t *testing.T) {
	content := `version: v1.25.0
ignore:
  SNYK-JS-FOO-1:
    - '*':
        reason: bad ts
        expires: not-a-date
patch: {}
`

	var p localpolicy.Policy
	err := localpolicy.Unmarshal(bytes.NewBufferString(content), &p)
	require.NoError(t, err, "legacy applies the rule with no expiry rather than failing the file")

	rule := p.Ignore["SNYK-JS-FOO-1"][0]["*"]
	require.NotNil(t, rule)
	assert.Equal(t, util.Ptr("bad ts"), rule.Reason)
	assert.Nil(t, rule.Expires)
}

func TestPolicy_Marshal(t *testing.T) {
	var buf bytes.Buffer
	p := localpolicy.New()
	p.Ignore["SNYK-GOLANG-PACKAGE-12345"] = append(p.Ignore["SNYK-GOLANG-PACKAGE-12345"], localpolicy.RuleEntry{
		"*": {
			Reason:             util.Ptr("none given"),
			DisregardIfFixable: util.Ptr(true),
		},
	})

	err := localpolicy.Marshal(&buf, p)
	require.NoError(t, err)

	assert.Equal(t, `version: v1.25.1
ignore:
    SNYK-GOLANG-PACKAGE-12345:
        - '*':
            reason: none given
            disregardIfFixable: true
patch: {}
`, buf.String())
}

func TestPolicy_Load(t *testing.T) {
	p, err := localpolicy.Load("testdata/ignore.yaml")
	require.NoError(t, err)

	assert.NotNil(t, p)
	assert.Equal(t, "v1.0.0", p.Version)
	assert.Len(t, p.Ignore, 5)
	assert.NotNil(t, p.Patch)
	assert.NotNil(t, (*p.Exclude)["global"])
}
