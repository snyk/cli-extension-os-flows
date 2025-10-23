package localpolicy_test

import (
	"bytes"
	_ "embed"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/util"
	"github.com/snyk/cli-extension-os-flows/pkg/localpolicy"
)

//go:embed testdata/ignore.yaml
var fixedPolicy []byte

func TestPolicy_New(t *testing.T) {
	p := localpolicy.New()

	assert.NotNil(t, p)
	assert.NotZero(t, p.Version)
	assert.NotNil(t, p.Ignore)
	assert.NotNil(t, p.Patch)
}

func TestPolicy_Unmarshal(t *testing.T) {
	buf := bytes.NewBuffer(fixedPolicy)
	var p localpolicy.Policy

	err := localpolicy.Unmarshal(buf, &p)
	require.NoError(t, err)

	assert.Equal(t, "v1.0.0", p.Version)
	assert.Len(t, p.Ignore, 5)

	ruleSet, ok := p.Ignore["npm:is-my-json-valid:20160118"]
	require.True(t, ok)
	require.Len(t, ruleSet, 1)
}

func TestPolicy_Marshal(t *testing.T) {
	var buf bytes.Buffer
	p := localpolicy.New()
	p.Ignore["SNYK-GOLANG-PACKAGE-12345"] = append(p.Ignore["SNYK-GOLANG-PACKAGE-12345"], localpolicy.RuleEntry{
		"*": {
			Reason:             util.Ptr("none given"),
			DisregardIfFixable: util.Ptr(true),
		},
	})

	err := localpolicy.Marshal(&buf, p)
	require.NoError(t, err)

	assert.Equal(t, `version: v1.25.1
ignore:
    SNYK-GOLANG-PACKAGE-12345:
        - '*':
            reason: none given
            disregardIfFixable: true
patch: {}
`, buf.String())
}

func TestPolicy_Load(t *testing.T) {
	p, err := localpolicy.Load("testdata/ignore.yaml")
	require.NoError(t, err)

	assert.NotNil(t, p)
	assert.Equal(t, "v1.0.0", p.Version)
	assert.Len(t, p.Ignore, 5)
}
