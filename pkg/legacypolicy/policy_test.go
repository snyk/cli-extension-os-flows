package legacypolicy_test

import (
	"bytes"
	_ "embed"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/pkg/legacypolicy"
)

//go:embed testdata/ignore.yaml
var fixedPolicy []byte

func TestPolicy_New(t *testing.T) {
	p := legacypolicy.New()

	assert.NotNil(t, p)
	assert.NotZero(t, p.Version)
	assert.NotNil(t, p.Ignore)
}

func TestPolicy_Unmarshal(t *testing.T) {
	buf := bytes.NewBuffer(fixedPolicy)
	var p legacypolicy.Policy

	err := legacypolicy.Unmarshal(buf, &p)
	require.NoError(t, err)

	assert.Equal(t, "v1.0.0", p.Version)
	assert.Len(t, p.Ignore, 5)

	ruleSet, ok := p.Ignore["npm:is-my-json-valid:20160118"]
	require.True(t, ok)
	require.Len(t, ruleSet, 1)
}

func TestPolicy_Marshal(t *testing.T) {
	var buf bytes.Buffer
	p := legacypolicy.New()
	p.Ignore["SNYK-GOLANG-PACKAGE-12345"] = append(p.Ignore["SNYK-GOLANG-PACKAGE-12345"], legacypolicy.RuleEntry{
		"*": {
			Reason:             "none given",
			DisregardIfFixable: true,
		},
	})

	err := legacypolicy.Marshal(&buf, p)
	require.NoError(t, err)

	assert.Equal(t, `version: v1.25.1
ignore:
    SNYK-GOLANG-PACKAGE-12345:
        - '*':
            reason: none given
            disregardIfFixable: true
`, buf.String())
}
