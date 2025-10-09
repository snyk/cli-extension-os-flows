package rubysemver

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
