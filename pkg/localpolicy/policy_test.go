package localpolicy_test

import (
	"bytes"
	"embed"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/util"
	"github.com/snyk/cli-extension-os-flows/pkg/localpolicy"
)

func TestPolicy_New(t *testing.T) {
	p := localpolicy.New()

	assert.NotNil(t, p)
	assert.NotZero(t, p.Version)
	assert.NotNil(t, p.Ignore)
	assert.NotNil(t, p.Patch)
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

const (
	validEmptyDir = "testdata/snyk-cases/validEmpty"
	validDataDir  = "testdata/snyk-cases/validData"
	formattingDir = "testdata/snyk-cases/formatting"
	invalidDir    = "testdata/snyk-cases/invalid"
)

//go:embed testdata/snyk-cases/validEmpty
var validEmptyCases embed.FS

//go:embed testdata/snyk-cases/validData
var validDataCases embed.FS

//go:embed testdata/snyk-cases/formatting
var formattingCases embed.FS

//go:embed testdata/snyk-cases/invalid
var invalidCases embed.FS

func TestPolicy_Unmarshal_ValidEmptyCases(t *testing.T) {
	testCases := []struct {
		file string
		want localpolicy.Policy
	}{{
		file: "comment-only.snyk",
		want: localpolicy.Policy{},
	}, {
		file: "empty-maps.snyk",
		want: localpolicy.Policy{
			Version: "v1.25.0",
			Ignore:  localpolicy.RuleSet{},
			Patch:   localpolicy.RuleSet{},
		},
	}, {
		file: "empty-seqs.snyk",
		want: localpolicy.Policy{
			Version: "v1.25.0",
			Ignore:  localpolicy.RuleSet{},
			Patch:   localpolicy.RuleSet{},
		},
	}, {
		file: "empty.snyk",
		want: localpolicy.Policy{},
	}, {
		file: "explicit-null.snyk",
		want: localpolicy.Policy{Version: "v1.25.0"},
	}, {
		file: "legacy-ts-default.snyk",
		want: localpolicy.Policy{
			Version: "v1.25.0",
			Ignore:  localpolicy.RuleSet{},
			Patch:   localpolicy.RuleSet{},
		},
	}, {
		file: "no-version.snyk",
		want: localpolicy.Policy{
			Ignore: localpolicy.RuleSet{},
			Patch:  localpolicy.RuleSet{},
		},
	}, {
		file: "null-ignore-patch.snyk",
		want: localpolicy.Policy{Version: "v1.25.0"},
	}, {
		file: "unknown-keys.snyk",
		want: localpolicy.Policy{
			Version: "v1.25.0",
			Ignore:  localpolicy.RuleSet{},
			Patch:   localpolicy.RuleSet{},
		},
	}, {
		file: "version-only.snyk",
		want: localpolicy.Policy{Version: "v1.25.0"},
	}, {
		file: "whitespace.snyk",
		want: localpolicy.Policy{},
	}, {
		file: "whitespace-tab.snyk",
		want: localpolicy.Policy{},
	}}

	for _, tc := range testCases {
		t.Run(tc.file, func(t *testing.T) {
			data, err := validEmptyCases.ReadFile(path.Join(validEmptyDir, tc.file))
			require.NoError(t, err)

			var p localpolicy.Policy
			require.NoError(t, localpolicy.Unmarshal(bytes.NewReader(data), &p))

			assert.Equal(t, tc.want, p)
		})
	}

	covered := make([]string, 0, len(testCases))
	for _, tc := range testCases {
		covered = append(covered, tc.file)
	}
	assertEveryCaseIsCovered(t, validEmptyCases, validEmptyDir, covered)
}

func TestPolicy_Unmarshal_ValidDataCases(t *testing.T) {
	const (
		vulnCXCT   = localpolicy.VulnID("SNYK-JS-CXCT-535487")
		vulnLodash = localpolicy.VulnID("SNYK-JS-LODASH-567746")
	)

	var (
		expires2099    = time.Date(2099, time.January, 1, 0, 0, 0, 0, time.UTC)
		expires2099Jun = time.Date(2099, time.June, 1, 0, 0, 0, 0, time.UTC)
		expired2020    = time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC)
		created2024    = time.Date(2024, time.January, 15, 9, 0, 0, 0, time.UTC)

		expires2116Milli136 = time.Date(2116, time.March, 1, 14, 30, 4, 136_000_000, time.UTC)
		expires2116Milli137 = time.Date(2116, time.March, 1, 14, 30, 4, 137_000_000, time.UTC)
	)

	testCases := []struct {
		file string
		want localpolicy.Policy
	}{{
		file: "disregard-if-fixable.snyk",
		want: localpolicy.Policy{
			Version: "v1.25.0",
			Ignore: localpolicy.RuleSet{
				vulnCXCT: {{"*": {
					Reason:             util.Ptr("disregard"),
					Expires:            util.Ptr(expires2099),
					DisregardIfFixable: util.Ptr(true),
				}}},
				vulnLodash: {{"*": {
					Reason:             util.Ptr("do not disregard"),
					Expires:            util.Ptr(expires2099),
					DisregardIfFixable: util.Ptr(false),
				}}},
			},
			Patch: localpolicy.RuleSet{},
		},
	}, {
		file: "exclude.snyk",
		want: localpolicy.Policy{
			Version: "v1.25.0",
			Ignore:  localpolicy.RuleSet{},
			Patch:   localpolicy.RuleSet{},
			Exclude: &map[string]any{"global": []any{"test/**"}},
		},
	}, {
		file: "expired.snyk",
		want: localpolicy.Policy{
			Version: "v1.25.0",
			Ignore: localpolicy.RuleSet{vulnCXCT: {{"*": {
				Reason:  util.Ptr("already expired"),
				Expires: util.Ptr(expired2020),
			}}}},
			Patch: localpolicy.RuleSet{},
		},
	}, {
		file: "fail-threshold.snyk",
		want: localpolicy.Policy{
			Version:       "v1.25.0",
			FailThreshold: util.Ptr(localpolicy.SeverityHigh),
			Ignore:        localpolicy.RuleSet{},
			Patch:         localpolicy.RuleSet{},
		},
	}, {
		file: "ignore-entry-null.snyk",
		want: localpolicy.Policy{
			Version: "v1.25.0",
			Ignore:  localpolicy.RuleSet{vulnCXCT: {{"*": {}}}},
			Patch:   localpolicy.RuleSet{},
		},
	}, {
		file: "multiple-entries.snyk",
		want: localpolicy.Policy{
			Version: "v1.25.0",
			Ignore: localpolicy.RuleSet{vulnCXCT: {
				{"*": {
					Reason:  util.Ptr("wildcard entry"),
					Expires: util.Ptr(expires2099),
				}},
				{"app > cxct": {
					Reason:             util.Ptr("specific entry"),
					Expires:            util.Ptr(expires2099),
					DisregardIfFixable: util.Ptr(true),
				}},
			}},
			Patch: localpolicy.RuleSet{},
		},
	}, {
		file: "multiple-vulns.snyk",
		want: localpolicy.Policy{
			Version: "v1.25.0",
			Ignore: localpolicy.RuleSet{
				vulnCXCT: {{"*": {
					Reason:  util.Ptr("first vuln"),
					Expires: util.Ptr(expires2099),
					Source:  util.Ptr("cli"),
				}}},
				vulnLodash: {{"*": {
					Reason:  util.Ptr("second vuln"),
					Expires: util.Ptr(expires2099Jun),
					IgnoredBy: &localpolicy.IgnoredBy{
						ID:    util.Ptr("00000000-0000-0000-0000-000000000001"),
						Name:  util.Ptr("Someone"),
						Email: util.Ptr("s@example.com"),
					},
				}}},
				"npm:hawk:20160119": {{"sqlite > sqlite3 > node-pre-gyp > request > hawk": {
					Reason:  util.Ptr("hawk got bumped"),
					Expires: util.Ptr(expires2116Milli136),
				}}},
				"npm:is-my-json-valid:20160118": {
					{"sqlite > sqlite3 > node-pre-gyp > request > har-validator > is-my-json-valid": {
						Reason:  util.Ptr("dev tool"),
						Expires: util.Ptr(expires2116Milli136),
					}},
				},
				"npm:tar:20151103": {{"sqlite > sqlite3 > node-pre-gyp > tar-pack > tar": {
					Reason:  util.Ptr("none given"),
					Expires: util.Ptr(expires2116Milli137),
				}}},
				"npm:method-override:20170927": {{"*": {
					Reason:             util.Ptr("none given"),
					DisregardIfFixable: util.Ptr(true),
				}}},
				"npm:marked:20170907": {{"*": {
					Reason:             util.Ptr("none given"),
					DisregardIfFixable: util.Ptr(true),
				}}},
			},
			Patch: localpolicy.RuleSet{},
		},
	}, {
		file: "no-expires.snyk",
		want: localpolicy.Policy{
			Version: "v1.25.0",
			Ignore:  localpolicy.RuleSet{vulnCXCT: {{"*": {Reason: util.Ptr("no expiry")}}}},
			Patch:   localpolicy.RuleSet{},
		},
	}, {
		file: "nonmatching-path.snyk",
		want: localpolicy.Policy{
			Version: "v1.25.0",
			Ignore: localpolicy.RuleSet{vulnCXCT: {{"some-other-pkg": {
				Reason:  util.Ptr("non matching path"),
				Expires: util.Ptr(expires2099),
			}}}},
			Patch: localpolicy.RuleSet{},
		},
	}, {
		file: "reason-type.snyk",
		want: localpolicy.Policy{
			Version: "v1.25.0",
			Ignore: localpolicy.RuleSet{vulnCXCT: {{"*": {
				Reason:     util.Ptr("rt"),
				ReasonType: util.Ptr(localpolicy.ReasonTypeWontFix),
				Created:    util.Ptr(created2024),
				Expires:    util.Ptr(expires2099),
				IgnoredBy: &localpolicy.IgnoredBy{
					Name:  util.Ptr("Someone"),
					Email: util.Ptr("s@example.com"),
				},
			}}}},
			Patch: localpolicy.RuleSet{},
		},
	}, {
		file: "specific-path.snyk",
		want: localpolicy.Policy{
			Version: "v1.25.0",
			Ignore: localpolicy.RuleSet{vulnCXCT: {{"cxct": {
				Reason:  util.Ptr("specific dep path"),
				Expires: util.Ptr(expires2099),
			}}}},
			Patch: localpolicy.RuleSet{},
		},
	}, {
		file: "tab-in-block-scalar.snyk",
		want: localpolicy.Policy{
			Version: "v1.25.0",
			Ignore: localpolicy.RuleSet{vulnCXCT: {{"*": {
				Reason: util.Ptr("accepted because\n\tthe tab is part of the text\n"),
			}}}},
			Patch: localpolicy.RuleSet{},
		},
	}, {
		file: "vuln-empty-seq.snyk",
		want: localpolicy.Policy{
			Version: "v1.25.0",
			Ignore:  localpolicy.RuleSet{vulnCXCT: {}},
		},
	}}

	for _, tc := range testCases {
		t.Run(tc.file, func(t *testing.T) {
			data, err := validDataCases.ReadFile(path.Join(validDataDir, tc.file))
			require.NoError(t, err)

			var p localpolicy.Policy
			require.NoError(t, localpolicy.Unmarshal(bytes.NewReader(data), &p))

			assert.Equal(t, tc.want, p)
		})
	}

	covered := make([]string, 0, len(testCases))
	for _, tc := range testCases {
		covered = append(covered, tc.file)
	}
	assertEveryCaseIsCovered(t, validDataCases, validDataDir, covered)
}

var (
	formattingCreated = time.Date(2021, time.January, 1, 0, 0, 0, 0, time.UTC)
	formattingExpires = time.Date(2099, time.January, 1, 0, 0, 0, 0, time.UTC)
)

func TestPolicy_Unmarshal_FormattingCases(t *testing.T) {
	forEachCase(t, formattingCases, formattingDir, func(t *testing.T, data []byte) {
		t.Helper()

		var p localpolicy.Policy
		require.NoError(t, localpolicy.Unmarshal(bytes.NewReader(data), &p))

		assert.Equal(t, "v1.25.0", p.Version)
		assert.Empty(t, p.Patch)
		assert.Nil(t, p.FailThreshold)
		assert.Nil(t, p.Exclude)

		require.Len(t, p.Ignore, 1)
		entries := p.Ignore[localpolicy.VulnID("SNYK-JS-CXCT-535487")]
		require.Len(t, entries, 1)

		rule, ok := entries[0][("*")]
		require.True(t, ok, "expected an ignore rule for dependency path %q", "*")
		require.NotNil(t, rule)

		require.NotNil(t, rule.Reason)
		assert.Equal(t, "formatting case", *rule.Reason)

		require.NotNil(t, rule.Created)
		assert.True(t, rule.Created.Equal(formattingCreated),
			"created: want %s, got %s", formattingCreated, rule.Created)

		require.NotNil(t, rule.Expires)
		assert.True(t, rule.Expires.Equal(formattingExpires),
			"expires: want %s, got %s", formattingExpires, rule.Expires)

		assert.Nil(t, rule.Patched)
		assert.Nil(t, rule.IgnoredBy)
		assert.Nil(t, rule.ReasonType)
		assert.Nil(t, rule.Source)
		assert.Nil(t, rule.From)
		assert.Nil(t, rule.DisregardIfFixable)
	})
}

func TestPolicy_Unmarshal_InvalidCases(t *testing.T) {
	testCases := []struct {
		file    string
		wantErr string
	}{{
		file:    "malformed-yaml.snyk",
		wantErr: "invalid .snyk policy: yaml: line 1: did not find expected ',' or ']'",
	}, {
		file:    "ignore-scalar.snyk",
		wantErr: `invalid .snyk policy: line 2: rule set must be a mapping, got scalar "nonsense"`,
	}, {
		file:    "ignore-nonempty-seq.snyk",
		wantErr: "invalid .snyk policy: line 3: rule set must be a mapping, got a non-empty sequence",
	}, {
		file:    "vuln-empty-map.snyk",
		wantErr: "old, unsupported .snyk format detected",
	}, {
		file:    "vuln-rule-body.snyk",
		wantErr: "old, unsupported .snyk format detected",
	}, {
		file:    "bad-timestamp.snyk",
		wantErr: "invalid .snyk policy: 'not-a-date' is not a valid timestamp",
	}, {
		file:    "toplevel-scalar.snyk",
		wantErr: `invalid .snyk policy: line 1: policy must be a mapping, got scalar "this is not valid yaml"`,
	}, {
		file:    "toplevel-seq.snyk",
		wantErr: "invalid .snyk policy: line 1: policy must be a mapping, got a sequence",
	}, {
		file:    "tabs.snyk",
		wantErr: "invalid .snyk policy: line 3: invalid indentation",
	}, {
		file:    "tabs-real-ignore.snyk",
		wantErr: "invalid .snyk policy: line 3: invalid indentation",
	}, {
		file:    "tabs-nested.snyk",
		wantErr: "invalid .snyk policy: line 5: invalid indentation",
	}, {
		file: "under-indented-rule.snyk",
		wantErr: `invalid .snyk policy: line 5: dependency path 'reason' must map to a set of ignore settings, ` +
			`but it is scalar "None Given"; check the indentation`,
	}, {
		file:    "ignored-by-scalar.snyk",
		wantErr: "invalid .snyk policy: line 5: cannot unmarshal !!str `someone`",
	}}

	for _, tc := range testCases {
		t.Run(tc.file, func(t *testing.T) {
			data, err := invalidCases.ReadFile(path.Join(invalidDir, tc.file))
			require.NoError(t, err)

			var p localpolicy.Policy
			err = localpolicy.Unmarshal(bytes.NewReader(data), &p)

			require.EqualError(t, err, tc.wantErr)
		})
	}

	covered := make([]string, 0, len(testCases))
	for _, tc := range testCases {
		covered = append(covered, tc.file)
	}
	assertEveryCaseIsCovered(t, invalidCases, invalidDir, covered)
}

func assertEveryCaseIsCovered(t *testing.T, cases embed.FS, dir string, covered []string) {
	t.Helper()

	t.Run("every case file is covered", func(t *testing.T) {
		inTable := make(map[string]bool, len(covered))
		for _, file := range covered {
			inTable[file] = true
		}

		entries, err := cases.ReadDir(dir)
		require.NoError(t, err)
		require.NotEmpty(t, entries)

		for _, entry := range entries {
			assert.True(t, inTable[entry.Name()], "%s has no row in the table", entry.Name())
		}
	})
}

func forEachCase(t *testing.T, cases embed.FS, dir string, check func(*testing.T, []byte)) {
	t.Helper()

	entries, err := cases.ReadDir(dir)
	require.NoError(t, err)
	require.NotEmpty(t, entries)

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		t.Run(entry.Name(), func(t *testing.T) {
			data, readErr := cases.ReadFile(path.Join(dir, entry.Name()))
			require.NoError(t, readErr)

			check(t, data)
		})
	}
}
