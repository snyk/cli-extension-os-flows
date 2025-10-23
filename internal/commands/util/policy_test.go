package util_test

import (
	"os"
	"path"
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	"github.com/snyk/cli-extension-os-flows/internal/commands/util"
	"github.com/snyk/cli-extension-os-flows/internal/flags"
)

func TestResolvePolicyFile_WithFilePath(t *testing.T) {
	tmpDotSnyk, err := os.CreateTemp("", ".snyk")
	require.NoError(t, err)
	t.Cleanup(func() { os.Remove(tmpDotSnyk.Name()) })

	cfg := configuration.New()
	cfg.Set(flags.FlagPolicyPath, tmpDotSnyk.Name())
	ctx := cmdctx.WithConfig(t.Context(), cfg)

	fd, err := util.ResolvePolicyFile(ctx)
	require.NoError(t, err)
	defer fd.Close()

	assert.NotNil(t, fd)
}

func TestResolvePolicyFile_NonexistentFile(t *testing.T) {
	cfg := configuration.New()
	cfg.Set(flags.FlagPolicyPath, "testdata/does-not-exist.yaml")
	ctx := cmdctx.WithConfig(t.Context(), cfg)

	_, err := util.ResolvePolicyFile(ctx)

	assert.ErrorContains(t, err, "failed to find .snyk file")
}

func TestResolvePolicyFile_WithDirectoryPath(t *testing.T) {
	dir, err := os.MkdirTemp("", "snyk-policy")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })

	tmpPolicy, err := os.Create(path.Join(dir, ".snyk"))
	require.NoError(t, err)

	cfg := configuration.New()
	cfg.Set(configuration.INPUT_DIRECTORY, dir)
	ctx := cmdctx.WithConfig(t.Context(), cfg)

	fd, err := util.ResolvePolicyFile(ctx)
	require.NoError(t, err)

	t.Cleanup(func() {
		tmpPolicy.Close()
		fd.Close()
	})

	assert.Equal(t, fd.Name(), tmpPolicy.Name())
}
