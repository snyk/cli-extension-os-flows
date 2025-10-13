package transform_test

import (
	"testing"
	"time"

	"github.com/gkampitakis/go-snaps/snaps"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/legacy/transform"
	"github.com/snyk/cli-extension-os-flows/pkg/legacypolicy"
)

func TestLegacyPolicyToLocalIgnores(t *testing.T) {
	p := &legacypolicy.Policy{
		Version: "v1.0.0",
		Ignore: legacypolicy.RuleSet{
			"npm:hawk:20160119": []legacypolicy.RuleEntry{
				{
					"sqlite > sqlite3 > node-pre-gyp > request > hawk": &legacypolicy.Rule{
						Reason:  "hawk got bumped",
						Expires: timeMustParse(t, "2116-03-01T14:30:04.136Z"),
					},
				},
			},
			"npm:method-override:20170927": []legacypolicy.RuleEntry{
				{
					"*": &legacypolicy.Rule{
						Reason:  "none given",
						Created: timeMustParse(t, "2022-04-10T15:56:02.074Z"),
					},
				},
			},
		},
	}
	lp, err := transform.LegacyPolicyToLocalPolicy(p)
	require.NoError(t, err)

	snaps.MatchStandaloneSnapshot(t, lp)
}

func timeMustParse(t *testing.T, val string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339Nano, val)
	require.NoError(t, err)
	return parsed
}
