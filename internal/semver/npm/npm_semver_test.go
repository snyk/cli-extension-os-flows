package npmsemver

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/semver/shared"
)

var (
	compare    shared.CompareFn
	satisfies  shared.SatisfiesFn
	valid      shared.ValidFn
	prerelease shared.PrereleaseFn
)

func init() {
	r, err := New()
	if err != nil {
		panic(err)
	}

	compare = r.Compare
	satisfies = r.Satisfies
	valid = r.Valid
	prerelease = r.Prerelease
}

func TestCompare(t *testing.T) {
	type testCase struct {
		lhs      string
		rhs      string
		expected int
	}

	tests := []testCase{
		// lhs == rhs
		{lhs: "v1.1.0", rhs: "v1.1.0", expected: 0},
		{lhs: "v1.10.0", rhs: "v1.10.0", expected: 0},
		{lhs: "v1.1.0-alpha", rhs: "v1.1.0-alpha", expected: 0},
		{lhs: "v1.1.0-alpha.2", rhs: "v1.1.0-alpha.2", expected: 0},
		{lhs: "v1.1.0-alpha+build", rhs: "v1.1.0-alpha+build", expected: 0},
		{lhs: "v1.1.0+build", rhs: "v1.1.0+build", expected: 0},

		// lhs < rhs
		{lhs: "v0.0.0", rhs: "v1.1.1", expected: -1},
		{lhs: "v1.1.0", rhs: "v1.1.1", expected: -1},
		{lhs: "v2.0.0", rhs: "v10.0.0", expected: -1},
		{lhs: "v1.2.0", rhs: "v1.10.1", expected: -1},
		{lhs: "v1.0.2", rhs: "v1.0.10", expected: -1},
		{lhs: "v1.1.10", rhs: "v1.2.1", expected: -1},
		{lhs: "v1.1.0-alpha", rhs: "v1.1.0-beta", expected: -1},
		{lhs: "v1.1.0-alpha.2", rhs: "v1.1.0-alpha.3", expected: -1},
		{lhs: "v1.0.0-20200221101010-abcdabcd", rhs: "v2.0.0-20200221101010-abcdabcd", expected: -1},
		{lhs: "v1.0.0-20200221101010-abcdabcd", rhs: "v1.0.0-20200229202020-abcd1234", expected: -1},
		{lhs: "v1.0.1-20200221101010-abcdabcd", rhs: "v1.0.1", expected: -1},
		{lhs: "v1.0.0", rhs: "v1.0.1-20200221101010-abcdabcd", expected: -1},
	}

	for _, tc := range tests {
		t.Run(tc.lhs+"_"+tc.rhs, func(t *testing.T) {
			got, err := compare(tc.lhs, tc.rhs)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, got)

			if tc.expected != 0 {
				got, err = compare(tc.rhs, tc.lhs)
				require.NoError(t, err)
				assert.Equal(t, -tc.expected, got)
			}
		})
	}
}

func TestSatisfies(t *testing.T) {
	type testCase struct {
		version      string
		versionRange string
		expected     bool
	}
	tests := []testCase{
		{version: "1.1.5", versionRange: "~> 1.1.2", expected: true},
		{version: "1.1.5", versionRange: "1.1.5", expected: true},
		{version: "1.4.11", versionRange: ">= 1.3", expected: true},
		{version: "1.4.11", versionRange: "< 1.5", expected: true},
		{version: "1.7.0-rc5", versionRange: "< 4.12.0", expected: true},
		{version: "1.2.5", versionRange: "~> 1.1.2", expected: false},
		{version: "1.2.5", versionRange: "1.1.2", expected: false},
		{version: "1.5.2", versionRange: "< 1.5", expected: false},
		{version: "1.2.1", versionRange: "nonsense", expected: false},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("version %s range %s", tc.version, tc.versionRange), func(t *testing.T) {
			assert.Equal(t, tc.expected, satisfies(tc.version, tc.versionRange))
		})
	}
}

func TestValid(t *testing.T) {
	type testCase struct {
		version  string
		expected string
	}

	tests := []testCase{
		// Valid versions (npm-semver returns the parsed version if the version is valid)
		{version: "v0.0.0", expected: "0.0.0"},
		{version: "v1.0.0", expected: "1.0.0"},
		{version: "v1.0.1", expected: "1.0.1"},
		{version: "v1.0.2", expected: "1.0.2"},
		{version: "v1.0.10", expected: "1.0.10"},
		{version: "v1.1.10", expected: "1.1.10"},
		{version: "v1.10.1", expected: "1.10.1"},
		{version: "v10.1.1", expected: "10.1.1"},
		{version: "v10.10.10", expected: "10.10.10"},
		{version: "v1.1.0-alpha", expected: "1.1.0-alpha"},
		{version: "v1.1.0-alpha.2", expected: "1.1.0-alpha.2"},
		{version: "v1.1.0-alpha.3", expected: "1.1.0-alpha.3"},
		{version: "v1.1.0-beta", expected: "1.1.0-beta"},
		{version: "v1.1.0-dev", expected: "1.1.0-dev"},
		{version: "v1.1.0-pre", expected: "1.1.0-pre"},
		{version: "v1.1.0+build", expected: "1.1.0"},
		{version: "v1.1.0+incompatible", expected: "1.1.0"},
		{version: "v1.1.0-alpha+build", expected: "1.1.0-alpha"},
		{version: "v0.0.0-20200221101010-abcdabcd", expected: "0.0.0-20200221101010-abcdabcd"},
		{version: "v0.0.0-20200221101010-abcdabcd+incompatible", expected: "0.0.0-20200221101010-abcdabcd"},
		{version: "v1.0.0-20200221101010-abcdabcd", expected: "1.0.0-20200221101010-abcdabcd"},
		{version: "v1.0.0-20200221101010-abcdabcd+incompatible", expected: "1.0.0-20200221101010-abcdabcd"},
		{version: "v1.0.0-20200229202020-abcd1234", expected: "1.0.0-20200229202020-abcd1234"},
		{version: "v1.0.1-20200221101010-abcdabcd", expected: "1.0.1-20200221101010-abcdabcd"},
		{version: "v2.0.0-20200221101010-abcdabcd", expected: "2.0.0-20200221101010-abcdabcd"},

		// Invalid versions (npm-semver returns the null if the version is invalid, and we convert it to empty string)
		{version: "v1", expected: ""},
		{version: "v2", expected: ""},
		{version: "v10", expected: ""},
		{version: "v1.10", expected: ""},
		{version: "v2.10", expected: ""},
		{version: "v10.0", expected: ""},
		{version: "v10.1", expected: ""},
		{version: "v10.2", expected: ""},
		{version: "1", expected: ""},
		{version: "1.0", expected: ""},
		{version: "1.0.0.0", expected: ""},
		{version: "v1.0.0.0", expected: ""},
		{version: "v1.0.0.0.0", expected: ""},
		{version: "v1-20200221101010-abcdabcd", expected: ""},
		{version: "v1.0-20200221101010-abcdabcd", expected: ""},
		{version: "a.b.c", expected: ""},
		{version: "nonsense", expected: ""},
	}

	for _, tc := range tests {
		t.Run(tc.version, func(t *testing.T) {
			got := valid(tc.version)
			assert.Equal(t, tc.expected, got)
		})
	}
}

func TestPrerelease(t *testing.T) {
	type testCase struct {
		version  string
		expected []string
	}

	tests := []testCase{
		// Regular versions (no prerelease components)
		{version: "1.0.0", expected: nil},
		{version: "v1.0.0", expected: nil},
		{version: "10.20.30", expected: nil},
		{version: "v2.1.5", expected: nil},

		// Simple prerelease versions
		{version: "1.0.0-alpha", expected: []string{"alpha"}},
		{version: "v1.0.0-alpha", expected: []string{"alpha"}},
		{version: "1.0.0-beta", expected: []string{"beta"}},
		{version: "1.0.0-rc", expected: []string{"rc"}},
		{version: "1.0.0-dev", expected: []string{"dev"}},
		{version: "1.0.0-pre", expected: []string{"pre"}},
		{version: "v0.5.4-pre", expected: []string{"pre"}},

		// Prerelease with numeric components
		{version: "1.0.0-alpha.1", expected: []string{"alpha", "1"}},
		{version: "v1.0.0-alpha.1", expected: []string{"alpha", "1"}},
		{version: "1.0.0-beta.2", expected: []string{"beta", "2"}},
		{version: "1.0.0-rc.3", expected: []string{"rc", "3"}},
		{version: "1.0.0-alpha.10", expected: []string{"alpha", "10"}},
		{version: "1.2.2-alpha.1", expected: []string{"alpha", "1"}},

		// Pure numeric prereleases (from npm semver tests)
		{version: "0.6.1-1", expected: []string{"1"}},
		{version: "1.0.0-123", expected: []string{"123"}},
		{version: "2.1.0-456", expected: []string{"456"}},

		// Complex prerelease versions
		{version: "1.0.0-alpha.1.2", expected: []string{"alpha", "1", "2"}},
		{version: "1.0.0-beta.2.3.4", expected: []string{"beta", "2", "3", "4"}},
		{version: "1.0.0-rc.1.alpha", expected: []string{"rc", "1", "alpha"}},

		// Prerelease with build metadata (build metadata should be ignored)
		{version: "1.0.0-alpha+build", expected: []string{"alpha"}},
		{version: "1.0.0-alpha.1+build.2", expected: []string{"alpha", "1"}},
		{version: "v1.0.0-beta.2+incompatible", expected: []string{"beta", "2"}},

		// Go-style pseudo versions
		{version: "v0.0.0-20200221101010-abcdabcd", expected: []string{"20200221101010-abcdabcd"}},
		{version: "v1.0.0-20200221101010-abcdabcd", expected: []string{"20200221101010-abcdabcd"}},
		{version: "v1.0.1-20200221101010-abcdabcd", expected: []string{"20200221101010-abcdabcd"}},
		{version: "v0.0.0-20200221101010-abcdabcd+incompatible", expected: []string{"20200221101010-abcdabcd"}},

		// Range syntax and invalid versions (should return nil)
		{version: "~2.0.0-alpha.1", expected: nil},
		{version: "^1.0.0-beta", expected: nil},
		{version: ">=1.0.0-alpha", expected: nil},
		{version: "v1", expected: nil},
		{version: "v1.0", expected: nil},
		{version: "1.0.0.0", expected: nil},
		{version: "nonsense", expected: nil},
		{version: "a.b.c", expected: nil},
		{version: "invalid version", expected: nil},
	}

	for _, tc := range tests {
		t.Run(tc.version, func(t *testing.T) {
			got := prerelease(tc.version)
			assert.Equal(t, tc.expected, got, "prerelease(%s) should return %v, got %v", tc.version, tc.expected, got)
		})
	}
}
