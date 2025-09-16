package rubysemver

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/semver/shared"
)

var (
	compare   shared.CompareFn
	satisfies shared.SatisfiesFn
	valid     shared.ValidFn
)

func init() {
	r, err := New()
	if err != nil {
		panic(err)
	}

	compare = r.Compare
	satisfies = r.Satisfies
	valid = r.Valid
}

func TestCompare(t *testing.T) {
	type testCase struct {
		lhs      string
		rhs      string
		expected int
	}

	tests := []testCase{
		// compare(v1, v2): 0 if v1 == v2
		{lhs: "1", rhs: "1", expected: 0},
		{lhs: "1.1", rhs: "1.1", expected: 0},
		{lhs: "1.1.0", rhs: "1.1.0", expected: 0},
		{lhs: "1.1.0.1", rhs: "1.1.0.1", expected: 0},
		{lhs: "1.1.0.1-alpha", rhs: "1.1.0.1-alpha", expected: 0},
		{lhs: "1.1.0.1-alpha.2", rhs: "1.1.0.1-alpha.2", expected: 0},

		// compare(v1, v2): 1 if v1 > v2
		{lhs: "2", rhs: "1", expected: 1},
		{lhs: "1.2", rhs: "1.1", expected: 1},
		{lhs: "1.1.1", rhs: "1.1.0", expected: 1},
		{lhs: "1.1.0.2", rhs: "1.1.0.1", expected: 1},
		{lhs: "1.1.0.1-beta", rhs: "1.1.0.1-alpha", expected: 1},
		{lhs: "1.1.0.1-alpha.3", rhs: "1.1.0.1-alpha.2", expected: 1},
		{lhs: "1.0.1-x86_64-linux", rhs: "1.0.0-java", expected: 1},
		{lhs: "1.0.0-x86_64-linux", rhs: "1.0.0-java", expected: 1},

		// compare(v1, v2): -1 if v1 < v2
		{lhs: "1", rhs: "2", expected: -1},
		{lhs: "1.1", rhs: "1.2", expected: -1},
		{lhs: "1.1.0", rhs: "1.1.1", expected: -1},
		{lhs: "1.1.0.1", rhs: "1.1.0.2", expected: -1},
		{lhs: "1.1.0.1-alpha", rhs: "1.1.0.1-beta", expected: -1},
		{lhs: "1.1.0.1-alpha.2", rhs: "1.1.0.1-alpha.3", expected: -1},
		{lhs: "1.0.0-x86_64-linux", rhs: "1.0.1-java", expected: -1},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("lhs %s rhs %s", tc.lhs, tc.rhs), func(t *testing.T) {
			got, err := compare(tc.lhs, tc.rhs)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, got)
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
		{version: "1.1", versionRange: ">= 1.1", expected: true},
		{version: "1.1.5", versionRange: "~> 1.1.2", expected: true},
		{version: "1.1.5", versionRange: "1.1.5", expected: true},
		{version: "1.4.11", versionRange: ">= 1.3, < 1.5", expected: true},
		{version: "1.0", versionRange: ">= 1.1", expected: false},
		{version: "1.2.5", versionRange: "~> 1.1.2", expected: false},
		{version: "1.2.5", versionRange: "1.1.2", expected: false},
		{version: "1.5.2", versionRange: ">= 1.3, < 1.5", expected: false},
		{version: "1.2.1", versionRange: "nonsense", expected: false},
		{version: "1.13.10-x86_64-darwin", versionRange: "< 1.14.0", expected: true},
		{version: "1.13.10-x86_64-darwin", versionRange: "> 1.14.0", expected: false},
		{version: "1.15.10-x86_64-darwin", versionRange: "> 1.14.0", expected: true},
		{version: "1.15.10-x86_64-darwin", versionRange: "< 1.14.0", expected: false},
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
		// Valid versions
		{version: "1", expected: "1"},
		{version: "1 ", expected: "1"},
		{version: " 1", expected: "1"},
		{version: "1.1", expected: "1.1"},
		{version: "1.1.2", expected: "1.1.2"},
		{version: "1.1.2.3", expected: "1.1.2.3"},
		{version: "1.1.2-4", expected: "1.1.2.pre.4"},
		{version: "1.1.2.pre.4", expected: "1.1.2.pre.4"},
		{version: "1.2<3", expected: "1.2<3"},
		{version: "1.2 3", expected: "1.2 3"},
		{version: "1.13.10-x86_64-darwin", expected: "1.13.10.pre.x86_64-darwin"},
		{version: "1.13.10-java", expected: "1.13.10.pre.java"},

		// Invalid versions
		{version: "", expected: ""},
		{version: "nonsense", expected: ""},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("version %s", tc.version), func(t *testing.T) {
			assert.Equal(t, tc.expected, valid(tc.version))
		})
	}
}
