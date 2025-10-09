package gosemver

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/pkg/semver/shared"
)

var compare shared.CompareFn

func init() {
	r, err := New()
	if err != nil {
		panic(err)
	}

	compare = r.Compare
}

func TestCompare(t *testing.T) {
	type testCase struct {
		lhs      string
		rhs      string
		expected int
	}

	tests := []testCase{
		// lhs == rhs
		{lhs: "v1", rhs: "v1", expected: 0},
		{lhs: "v1.1", rhs: "v1.1", expected: 0},
		{lhs: "v1.1.0", rhs: "v1.1.0", expected: 0},
		{lhs: "v1.10.0", rhs: "v1.10.0", expected: 0},
		{lhs: "v1.1.0-alpha", rhs: "v1.1.0-alpha", expected: 0},
		{lhs: "v1.1.0-alpha.2", rhs: "v1.1.0-alpha.2", expected: 0},
		{lhs: "v1.1.0-alpha+build", rhs: "v1.1.0-alpha+build", expected: 0},
		{lhs: "v1.1.0+build", rhs: "v1.1.0+build", expected: 0},

		// lhs < rhs
		{lhs: "v1", rhs: "v2", expected: -1},
		{lhs: "v2", rhs: "v10", expected: -1},
		{lhs: "v1.1", rhs: "v1.2", expected: -1},
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
		{lhs: "v0.0.0", rhs: "v0.0.0-20200221101010-abcdabcd", expected: -1},
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
