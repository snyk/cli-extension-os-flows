package mavensemver

import (
	"fmt"
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
