package policy_test

import (
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/policy"
)

func TestPolicy_Load_WithFilePath(t *testing.T) {
	tmpDotSnyk, err := os.CreateTemp("", ".snyk")
	require.NoError(t, err)
	t.Cleanup(func() { os.Remove(tmpDotSnyk.Name()) })

	fd, err := policy.Resolve(tmpDotSnyk.Name())
	require.NoError(t, err)
	assert.NotNil(t, fd)

	t.Cleanup(func() { fd.Close() })
}

func TestPolicy_Load_NonexistentFile(t *testing.T) {
	_, err := policy.Resolve("testdata/does-not-exist.yaml")
	assert.ErrorContains(t, err, "failed to find .snyk file")
}

func TestPolicy_Load_WithDirectoryPath(t *testing.T) {
	dir, err := os.MkdirTemp("", "snyk-policy")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })

	tmpPolicy, err := os.Create(path.Join(dir, ".snyk"))
	require.NoError(t, err)

	fd, err := policy.Resolve(dir)
	require.NoError(t, err)

	t.Cleanup(func() {
		tmpPolicy.Close()
		fd.Close()
	})

	assert.Equal(t, fd.Name(), tmpPolicy.Name())
}
