package mavensemver

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
		{lhs: "1.1.0.1-alpha", rhs: "1.1.0.1-ALPHA", expected: 0},
		{lhs: "1.1.0.1-alpha.2", rhs: "1.1.0.1-Alpha.2", expected: 0},
		{lhs: "1.1.0.Final", rhs: "1.1.0", expected: 0},
		{lhs: "1.1.0-GA", rhs: "1.1.0", expected: 0},
		{lhs: "1.1.0.RELEASE", rhs: "1.1.0", expected: 0},
		{lhs: "1.1.0.1-alpha1", rhs: "1.1.0.1-a1", expected: 0},
		{lhs: "1.0-alpha1", rhs: "1.0-a1", expected: 0},
		{lhs: "1.0-beta1", rhs: "1.0-b1", expected: 0},
		{lhs: "1.0-milestone1", rhs: "1.0-m1", expected: 0},
		{lhs: "1.0-rc1", rhs: "1.0-cr1", expected: 0},
		{lhs: "1.0alpha1", rhs: "1.0-a1", expected: 0},
		{lhs: "1.0alpha-1", rhs: "1.0-a1", expected: 0},
		{lhs: "1.0beta1", rhs: "1.0-b1", expected: 0},
		{lhs: "1.0beta-1", rhs: "1.0-b1", expected: 0},
		{lhs: "1.0milestone1", rhs: "1.0-m1", expected: 0},
		{lhs: "1.0milestone-1", rhs: "1.0-m1", expected: 0},
		{lhs: "1.0rc1", rhs: "1.0-cr1", expected: 0},
		{lhs: "1.0rc-1", rhs: "1.0-cr1", expected: 0},
		{lhs: "1.0ga", rhs: "1.0", expected: 0},
		{lhs: "1.0MILESTONE1", rhs: "1.0-m1", expected: 0},
		{lhs: "1.0RC1", rhs: "1.0-cr1", expected: 0},
		{lhs: "1.0.0.0.0.0.0", rhs: "1", expected: 0},
		{lhs: "1.0.0.0.0.0.0x", rhs: "1x", expected: 0},

		// compare(v1, v2): 1 if v1 > v2
		{lhs: "2", rhs: "1", expected: 1},
		{lhs: "1.2", rhs: "1.1", expected: 1},
		{lhs: "1.1.1", rhs: "1.1.0", expected: 1},
		{lhs: "1.1.0.2", rhs: "1.1.0.1", expected: 1},
		{lhs: "1.1.1", rhs: "1.1.1.beta", expected: 1},
		{lhs: "1.1.0.1-beta", rhs: "1.1.0.1-alpha", expected: 1},
		{lhs: "1.1.0.1-alpha.3", rhs: "1.1.0.1-alpha.2", expected: 1},
		{lhs: "1.1.1.Final", rhs: "1.1.0", expected: 1},
		{lhs: "1.1.0.1-GA", rhs: "1.1.0.beta", expected: 1},
		{lhs: "1.1.1.RELEASE", rhs: "1.1.0", expected: 1},
		{lhs: "1.1.0-jre", rhs: "1.1.0", expected: 1},

		// compare(v1, v2): -1 if v1 < v2
		{lhs: "0.0.0-2022-07-26T05-45-04-226aabd9", rhs: "0.0.0-2022-10-29T03-41-04-bb4a3b2b", expected: -1},
		{lhs: "1", rhs: "2", expected: -1},
		{lhs: "1.1", rhs: "1.2", expected: -1},
		{lhs: "1.1.0", rhs: "1.1.1", expected: -1},
		{lhs: "1.1.0.1", rhs: "1.1.0.2", expected: -1},
		{lhs: "1.1.0.1-alpha", rhs: "1.1.0.1-beta", expected: -1},
		{lhs: "1.1.0.1-alpha.2", rhs: "1.1.0.1-alpha.3", expected: -1},
		{lhs: "1.1.1.Final", rhs: "1.1.2", expected: -1},
		{lhs: "1.1.0.1-GA", rhs: "1.1.2.beta", expected: -1},
		{lhs: "1.1.1.RELEASE", rhs: "1.1.2", expected: -1},
		{lhs: "1.1.1-jre", rhs: "1.1.2", expected: -1},
		{lhs: "1.1.0.1-alpha", rhs: "1.1.0.1-a", expected: -1},
		{lhs: "SomeRandomVersionOne", rhs: "SOMERANDOMVERSIONTWO", expected: -1},
		{lhs: "SomeRandomVersionThree", rhs: "SOMERANDOMVERSIONTWO", expected: -1},
		{lhs: "1.5-M2.1", rhs: "1.5", expected: -1},
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
		{version: "0", versionRange: "(,)", expected: true},
		{version: "0", versionRange: "[,]", expected: true},
		{version: "0.1", versionRange: "(,)", expected: true},
		{version: "0.9.0", versionRange: "(,1.0],[1.2,)", expected: true},
		{version: "1", versionRange: "(,)", expected: true},
		{version: "1", versionRange: "[,]", expected: true},
		{version: "1-a", versionRange: "(1,2)", expected: true},
		{version: "1-alpha", versionRange: "(,)", expected: true},
		{version: "1-alpha", versionRange: "[,]", expected: true},
		{version: "1.0", versionRange: "(,)", expected: true},
		{version: "1.0", versionRange: "[,]", expected: true},
		{version: "1.0", versionRange: "[,]", expected: true},
		{version: "1.0-alpha", versionRange: "[1-alpha,1)", expected: true},
		{version: "1.0-alpha", versionRange: "[1-alpha,1]", expected: true},
		{version: "1.0-alpha", versionRange: "[1-alpha,2)", expected: true},
		{version: "1.0-alpha", versionRange: "[1.0-alpha,1]", expected: true},
		{version: "1.0-alpha1", versionRange: "(,)", expected: true},
		{version: "1.0-alpha1", versionRange: "[,]", expected: true},
		{version: "1.0-alpha1", versionRange: "[1-a1,2)", expected: true},
		{version: "1.0-beta", versionRange: "[1-a1,2)", expected: true},
		{version: "1.0-final", versionRange: "[1,1-a]", expected: true},
		{version: "1.1", versionRange: "[1.1,)", expected: true},
		{version: "1.1.1-FINAL", versionRange: "(,)", expected: true},
		{version: "1.1.1-FINAL", versionRange: "[,]", expected: true},
		{version: "1.1.1-jre", versionRange: "[,]", expected: true},
		{version: "1.1.5", versionRange: "1.1.5", expected: true},
		{version: "1.2.3", versionRange: "(,1.0],[1.2,)", expected: true},
		{version: "1.2.3", versionRange: "[1.2,)", expected: true},
		{version: "1.4.11", versionRange: "[1.3,1.5)", expected: true},
		{version: "1.milestone2", versionRange: "[,1.milestone3)", expected: true},
		{version: "1.milestone2", versionRange: "[,1.milestone3]", expected: true},
		{version: "10", versionRange: "[10.+,)", expected: true},
		{version: "10.1", versionRange: "[10.+,)", expected: true},
		{version: "10.1", versionRange: "[10.1.+,)", expected: true},
		{version: "11", versionRange: "[10.+,)", expected: true},
		{version: "2", versionRange: "[,2.0-FINAL]", expected: true},
		{version: "2.0", versionRange: "[,2.0-FINAL]", expected: true},
		{version: "2.0.0.GA", versionRange: "[,2.0-FINAL]", expected: true},
		{version: "2.0.0.RELEASE", versionRange: "[,2.0-FINAL]", expected: true},
		{version: "2.0.FINAL", versionRange: "[,2]", expected: true},
		{version: "2.0.alpha", versionRange: "[,2.0)", expected: true},
		{version: "2.5", versionRange: "[2.5,2.5.6.SEC02)", expected: true},
		{version: "2.5-SNAPSHOT", versionRange: "[2.5-alpha,2.5.6.SEC02)", expected: true},
		{version: "2.5.6-SNAPSHOT", versionRange: "[2.5,2.5.6.SEC02)", expected: true},
		{version: "2.5.6.SEC01", versionRange: "[2.5,2.5.6.SEC02)", expected: true},
		{version: "2.5.6.SECURITY01", versionRange: "[2.5,2.5.6.SEC02)", expected: true},
		{version: "2.FINAL", versionRange: "[,2.0-GA]", expected: true},
		{version: "2.alpha", versionRange: "[,2.beta)", expected: true},
		{version: "3.2.7.RELEASE", versionRange: "[3,3.2.9)", expected: true},
		{version: "3.3.4", versionRange: "[3.3.0,3.4.7), [3.5,3.5.1),", expected: true},
		{version: "3.alpha", versionRange: "[2,3]", expected: true},
		{version: "4.1.0-jre", versionRange: "(4.1.0,4.3.0]", expected: true},
		{version: "4.1.0-jre", versionRange: "[4.1.0,4.3.0]", expected: true},
		{version: "4.1.0.Final", versionRange: "[4.1.0,4.3.0]", expected: true},
		{version: "4.3.0.Final", versionRange: "[4.1.0,4.3.0]", expected: true},
		{version: "4.3.0.GA", versionRange: "[4.1.0,4.3.0]", expected: true},
		{version: "4.3.0.RELEASE", versionRange: "[4.1.0,4.3.0]", expected: true},
		{version: "4.3.0.alpha", versionRange: "[4.1.0,4.3.0]", expected: true},
		{version: "nonsense", versionRange: "nonsense", expected: true},

		{version: "0.9", versionRange: "[1-a,2)", expected: false},
		{version: "1", versionRange: "", expected: false},
		{version: "1.0", versionRange: "[1.1,)", expected: false},
		{version: "1.0-alpha", versionRange: "[1,1.0-alpha]", expected: false},
		{version: "1.0-final", versionRange: "(1,1-a]", expected: false},
		{version: "1.0-final", versionRange: "[1-a,1)", expected: false},
		{version: "1.1.5", versionRange: "1.1.2", expected: false},
		{version: "1.1.5", versionRange: "[1.1.2]", expected: false},
		{version: "1.1.8", versionRange: "(,1.0],[1.2,)", expected: false},
		{version: "1.2", versionRange: "1.1", expected: false},
		{version: "1.2.1", versionRange: "nonsense", expected: false},
		{version: "1.5.2", versionRange: "[1.3,1.5)", expected: false},
		{version: "1.milestone2", versionRange: "[,1.milestone1]", expected: false},
		{version: "10.0", versionRange: "[10.1.+,)", expected: false},
		{version: "2.5-SNAPSHOT", versionRange: "[2.5,2.5.6.SEC02)", expected: false},
		{version: "2.5.6.SEC02", versionRange: "[2.5,2.5.6.SEC02)", expected: false},
		{version: "2.alpha", versionRange: "[2,3]", expected: false},
		{version: "2.beta", versionRange: "[,2.beta)", expected: false},
		{version: "4.0.9-jre", versionRange: "[3,3.0.6)", expected: false},
		{version: "4.0.9.RELEASE", versionRange: "[,2.5.6.REC03)", expected: false},
		{version: "4.0.9.RELEASE", versionRange: "[,2.5.6.SEC03), [2.5.7,2.5.7.SR023), [3,3.0.6)", expected: false},
		{version: "4.0.9.RELEASE", versionRange: "[2.5.7,2.5.7.SR023)", expected: false},
		{version: "4.0.9.RELEASE", versionRange: "[3,3.0.6)", expected: false},
		{version: "4.1.0.beta", versionRange: "[4.1.0,4.3.0]", expected: false},
		{version: "4.2.1", versionRange: "[2.0.0,3)", expected: false},
		{version: "4.2.1", versionRange: "[2.0.0,3),[3.0.0.RELEASE,3.1),[3.1.0.RELEASE,3.2)", expected: false},
		{version: "4.2.1.RELEASE", versionRange: "(4.1.0.RELEASE,4.2.0.RELEASE)", expected: false},
		{version: "4.3.0-jre", versionRange: "[4.1.0,4.3.0]", expected: false},
		{version: "4.3.0.GA", versionRange: "[4.1.0,4.3.0)", expected: false},
		{version: "9", versionRange: "[10.+,)", expected: false},
		{version: "nonsense", versionRange: "other", expected: false},
		{version: "unknown", versionRange: "(,)", expected: false},
		{version: "unknown", versionRange: "1.1", expected: false},
		{version: "unknown", versionRange: "[,2]", expected: false},
		{version: "unknown", versionRange: "[,]", expected: false},
		{version: "unknown", versionRange: "[1,)", expected: false},
		{version: "unknown", versionRange: "[10.+,)", expected: false},
		{version: "unknown", versionRange: "nonsense", expected: false},
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
		{version: "nonsense", expected: "nonsense"},
		{version: "1", expected: "1"},
		{version: "1.1", expected: "1.1"},
		{version: "1.1.2", expected: "1.1.2"},
		{version: "1.1.2.3", expected: "1.1.2.3"},
		{version: "1.1.2.", expected: "1.1.2"},
		{version: "1.1.2.GA", expected: "1.1.2"},
		{version: "1.1.2-Final", expected: "1.1.2"},
		{version: "1.1.2.RELEASE-3", expected: "1.1.2-3"},
		{version: "1.1.2.GA-almost", expected: "1.1.2-almost"},
		{version: "1.1.2.GA.almost", expected: "1.1.2-ga.almost"},
		{version: "1.1.2-4", expected: "1.1.2-4"},
		{version: "1.2-12-alpha-4", expected: "1.2-12-alpha-4"},
		{version: "1.2-12alpha-4", expected: "1.2-12-alpha-4"},
		{version: "1.2-alpha34-4", expected: "1.2-alpha-34-4"},
		{version: "1.2alpha34-4", expected: "1.2-alpha-34-4"},
		{version: "1.2ga34-4", expected: "1.2-34-4"},
		{version: "1.2alpha34BEtA4", expected: "1.2-alpha-34-beta-4"},
		{version: "1.1.2-4", expected: "1.1.2-4"},
		{version: "1.2-12-ga-4", expected: "1.2-12-4"},
		{version: "1.2-12Final-4", expected: "1.2-12-4"},
		{version: "1.2-release34-4", expected: "1.2-34-4"},
		{version: "1.2-release-34-4", expected: "1.2-34-4"},
		{version: "1.2ga34-4", expected: "1.2-34-4"},
		{version: "1.2FiNaL34BEtA4", expected: "1.2-34-beta-4"},

		// Invalid versions
		{version: "", expected: ""},
		{version: ".", expected: ""},
		{version: ".-.", expected: ""},
		{version: "unknown", expected: ""},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("version %s", tc.version), func(t *testing.T) {
			assert.Equal(t, tc.expected, valid(tc.version))
		})
	}
}
