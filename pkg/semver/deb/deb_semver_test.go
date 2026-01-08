package debsemver

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
		{lhs: "1.0-1", rhs: "1.0-1", expected: 0},
		{lhs: "1:1.0", rhs: "1:1.0", expected: 0},
		{lhs: "1:1.0-1", rhs: "1:1.0-1", expected: 0},

		{lhs: "1.0-1ubuntu1", rhs: "1.0-1ubuntu1", expected: 0},
		{lhs: "2.5.3-2", rhs: "2.5.3-2", expected: 0},

		{lhs: "2:1.0", rhs: "2:1.0", expected: 0},
		{lhs: "5:4.3.2-1", rhs: "5:4.3.2-1", expected: 0},

		{lhs: "1.0", rhs: "2.0", expected: -1},
		{lhs: "1.0.0", rhs: "1.0.1", expected: -1},
		{lhs: "1.0.0", rhs: "1.1.0", expected: -1},
		{lhs: "1.0.0", rhs: "2.0.0", expected: -1},
		{lhs: "1.9", rhs: "1.10", expected: -1},
		{lhs: "2.0", rhs: "10.0", expected: -1},

		{lhs: "1.0-1", rhs: "1.0-2", expected: -1},
		{lhs: "1.0-1", rhs: "1.0-10", expected: -1},
		{lhs: "1.0", rhs: "1.0-1", expected: -1},
		{lhs: "1.0-1ubuntu1", rhs: "1.0-1ubuntu2", expected: -1},
		{lhs: "1.0-1", rhs: "1.0-1ubuntu1", expected: -1},

		{lhs: "1.0", rhs: "1:0.1", expected: -1},
		{lhs: "1:1.0", rhs: "2:0.1", expected: -1},
		{lhs: "0:2.0", rhs: "1:1.0", expected: -1},
		{lhs: "1:1.0-1", rhs: "2:1.0-1", expected: -1},

		{lhs: "1:1.0-1", rhs: "1:1.0-2", expected: -1},
		{lhs: "1:1.0-1", rhs: "1:2.0-1", expected: -1},
		{lhs: "2:1.0-1", rhs: "2:1.0-1ubuntu1", expected: -1},

		{lhs: "1.0a", rhs: "1.0b", expected: -1},
		{lhs: "1.0", rhs: "1.0a", expected: -1},
		{lhs: "1.0~beta", rhs: "1.0", expected: -1}, // tilde makes it sort before
		{lhs: "1.0~rc1", rhs: "1.0~rc2", expected: -1},
		{lhs: "1.0~rc2", rhs: "1.0", expected: -1},

		{lhs: "2.6.32-5", rhs: "2.6.32-5+deb6u1", expected: -1},
		{lhs: "1:2.6.32-5", rhs: "1:2.6.32-5+deb6u1", expected: -1},
		{lhs: "1.2.3-1ubuntu1", rhs: "1.2.3-1ubuntu1.1", expected: -1},
		{lhs: "1.0+git20200101", rhs: "1.0+git20200102", expected: -1},
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
