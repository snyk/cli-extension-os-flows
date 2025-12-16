package util_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/snyk/cli-extension-os-flows/pkg/flags"

	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	"github.com/snyk/cli-extension-os-flows/internal/commands/util"
)

var nopLogger = zerolog.Nop()

func TestGetLocalPolicy_WithFilePath(t *testing.T) {
	tmpDotSnyk, err := os.CreateTemp("", ".snyk")
	require.NoError(t, err)
	defer tmpDotSnyk.Close()
	t.Cleanup(func() { os.Remove(tmpDotSnyk.Name()) })
	_, err = tmpDotSnyk.WriteString("version: v1.0.0\n")
	require.NoError(t, err)

	cfg := configuration.New()
	cfg.Set(flags.FlagPolicyPath, tmpDotSnyk.Name())
	ctx := cmdctx.WithConfig(t.Context(), cfg)
	ctx = cmdctx.WithLogger(ctx, &nopLogger)

	policy, err := util.GetLocalPolicy(ctx, ".")
	require.NoError(t, err)

	assert.NotNil(t, policy)
	assert.Equal(t, "v1.0.0", policy.Version)
}

func TestResolvePolicyFile_NonexistentFile(t *testing.T) {
	cfg := configuration.New()
	cfg.Set(flags.FlagPolicyPath, "testdata/does-not-exist.yaml")
	ctx := cmdctx.WithConfig(t.Context(), cfg)
	ctx = cmdctx.WithLogger(ctx, &nopLogger)

	policy, err := util.GetLocalPolicy(ctx, ".")

	assert.NoError(t, err)
	assert.Nil(t, policy)
}

func TestResolvePolicyFile_WithDirectoryPath(t *testing.T) {
	dir, err := os.MkdirTemp("", "snyk-policy")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })

	tmpPolicy, err := os.Create(filepath.Join(dir, ".snyk"))
	require.NoError(t, err)
	defer tmpPolicy.Close()

	_, err = tmpPolicy.WriteString("version: the-version\n")
	require.NoError(t, err)

	cfg := configuration.New()
	ctx := cmdctx.WithConfig(t.Context(), cfg)
	ctx = cmdctx.WithLogger(ctx, &nopLogger)

	policy, err := util.GetLocalPolicy(ctx, dir)
	require.NoError(t, err)

	require.NotNil(t, policy)
	assert.Equal(t, "the-version", policy.Version)
}

func TestResolvePolicyFile_NoPolicyFile(t *testing.T) {
	dir, err := os.MkdirTemp("", "snyk-policy")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })

	cfg := configuration.New()
	ctx := cmdctx.WithConfig(t.Context(), cfg)
	ctx = cmdctx.WithLogger(ctx, &nopLogger)

	policy, err := util.GetLocalPolicy(ctx, dir)

	assert.Nil(t, policy)
	assert.NoError(t, err)
}

func TestGetLocalPolicy_BrokenPolicy(t *testing.T) {
	dir, err := os.MkdirTemp("", "snyk-policy")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })

	tmpPolicy, err := os.Create(filepath.Join(dir, ".snyk"))
	require.NoError(t, err)
	defer tmpPolicy.Close()

	_, err = tmpPolicy.WriteString(`¯\_(ツ)_/¯`)
	require.NoError(t, err)

	cfg := configuration.New()
	ctx := cmdctx.WithConfig(t.Context(), cfg)
	ctx = cmdctx.WithLogger(ctx, &nopLogger)

	policy, err := util.GetLocalPolicy(ctx, dir)

	require.Nil(t, policy)
	var terr *yaml.TypeError
	assert.ErrorAs(t, err, &terr)
}

func TestGetLocalPolicy_WhenDotSnykIsADir(t *testing.T) {
	dir, err := os.MkdirTemp("", "snyk-policy")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })

	err = os.Mkdir(filepath.Join(dir, ".snyk"), 0o755)
	require.NoError(t, err)

	cfg := configuration.New()
	ctx := cmdctx.WithConfig(t.Context(), cfg)
	ctx = cmdctx.WithLogger(ctx, &nopLogger)

	policy, err := util.GetLocalPolicy(ctx, dir)

	require.NoError(t, err)
	require.Nil(t, policy)
}
