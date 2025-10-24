package localpolicy_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/util"
	"github.com/snyk/cli-extension-os-flows/pkg/localpolicy"
)

func TestPolicy_AddIgnore(t *testing.T) {
	p := localpolicy.New()

	p.AddIgnore("npm:hawk:20160119", []string{"sqlite", "sqlite3", "node-pre-gyp", "request", "hawk"}, &localpolicy.Rule{
		Reason:  util.Ptr("hawk got bumped"),
		Expires: util.Ptr(time.Date(2025, 6, 3, 7, 41, 24, 0, time.UTC)),
	})

	entries, ok := p.Ignore["npm:hawk:20160119"]
	require.True(t, ok)
	require.Len(t, entries, 1)
	ignore := entries[0]
	rule, ok := ignore["sqlite > sqlite3 > node-pre-gyp > request > hawk"]
	require.True(t, ok)

	assert.NotNil(t, rule)
	assert.Equal(t, "hawk got bumped", *rule.Reason)
}
