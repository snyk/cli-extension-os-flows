package alpinesemver

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
		{lhs: "1.0", rhs: "1.0", expected: 0},
		{lhs: "1.0.0", rhs: "1.0.0", expected: 0},
		{lhs: "2.5.3", rhs: "2.5.3", expected: 0},
		{lhs: "1.0-r0", rhs: "1.0-r0", expected: 0},
		{lhs: "1.0.0-r1", rhs: "1.0.0-r1", expected: 0},

		{lhs: "1.0_alpha", rhs: "1.0_alpha", expected: 0},
		{lhs: "1.0_beta1", rhs: "1.0_beta1", expected: 0},
		{lhs: "1.0_rc1", rhs: "1.0_rc1", expected: 0},
		{lhs: "1.0_pre1", rhs: "1.0_pre1", expected: 0},

		{lhs: "1.0", rhs: "2.0", expected: -1},
		{lhs: "1.0.0", rhs: "1.0.1", expected: -1},
		{lhs: "1.0.0", rhs: "1.1.0", expected: -1},
		{lhs: "1.0.0", rhs: "2.0.0", expected: -1},
		{lhs: "1.9", rhs: "1.10", expected: -1},
		{lhs: "2.0", rhs: "10.0", expected: -1},

		{lhs: "1.0-r0", rhs: "1.0-r1", expected: -1},
		{lhs: "1.0-r1", rhs: "1.0-r10", expected: -1},
		{lhs: "1.0.0-r0", rhs: "1.0.0-r1", expected: -1},

		{lhs: "1.0_alpha", rhs: "1.0_beta", expected: -1},
		{lhs: "1.0_beta", rhs: "1.0_pre", expected: -1},
		{lhs: "1.0_pre", rhs: "1.0_rc", expected: -1},
		{lhs: "1.0_rc", rhs: "1.0", expected: -1},
		{lhs: "1.0_alpha", rhs: "1.0", expected: -1},
		{lhs: "1.0_alpha1", rhs: "1.0_alpha2", expected: -1},
		{lhs: "1.0_beta1", rhs: "1.0_beta2", expected: -1},
		{lhs: "1.0_rc1", rhs: "1.0_rc2", expected: -1},

		{lhs: "1.0_alpha-r0", rhs: "1.0_alpha-r1", expected: -1},
		{lhs: "1.0_rc1-r0", rhs: "1.0_rc1-r1", expected: -1},
		{lhs: "1.0_rc1-r0", rhs: "1.0-r0", expected: -1},

		{lhs: "1.0a", rhs: "1.0b", expected: -1},
		{lhs: "1.0", rhs: "1.0a", expected: -1},

		{lhs: "1.0.0_p1", rhs: "1.0.0_p2", expected: -1},
		{lhs: "1.0.0", rhs: "1.0.0_p2", expected: -1},

		{lhs: "3.12.1-r0", rhs: "3.12.1-r1", expected: -1},
		{lhs: "2.38.1-r0", rhs: "2.38.2-r0", expected: -1},
		{lhs: "1.2.3_rc1-r0", rhs: "1.2.3-r0", expected: -1},
		{lhs: "1.0.0_alpha20200101", rhs: "1.0.0_alpha20200102", expected: -1},
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
