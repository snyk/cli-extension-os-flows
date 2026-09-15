package transform_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	"github.com/snyk/cli-extension-os-flows/internal/errors"
	"github.com/snyk/cli-extension-os-flows/internal/legacy/transform"
)

const (
	rootPolicyYAML = `version: v1.25.0
ignore:
  SNYK-JS-CXCT-535487:
    - '*':
        reason: root-level ignore that no project opted into
        expires: 2099-01-01T00:00:00.000Z
patch: {}
`
	projectPolicyYAML = `version: v1.25.0
ignore:
  SNYK-JS-CXCT-535487:
    - '*':
        reason: the project's own ignore
        expires: 2099-01-01T00:00:00.000Z
patch: {}
`
)

func writePolicy(t *testing.T, dir, contents string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".snyk"), []byte(contents), 0o600))
}

func TestConvertSnykSchemaFindingsToLegacy_ResolvesPolicyFromPolicyDir(t *testing.T) {
	scanRoot := t.TempDir()
	projectDir := filepath.Join(scanRoot, "proj-a")
	require.NoError(t, os.Mkdir(projectDir, 0o750))

	writePolicy(t, scanRoot, rootPolicyYAML)
	writePolicy(t, projectDir, projectPolicyYAML)

	logger := zerolog.Nop()
	ctx := cmdctx.WithLogger(t.Context(), &logger)
	ctx = cmdctx.WithConfig(ctx, configuration.NewWithOpts())

	res, err := transform.ConvertSnykSchemaFindingsToLegacy(ctx, &transform.SnykSchemaToLegacyParams{
		TargetDir:  scanRoot,
		PolicyDir:  projectDir,
		ErrFactory: errors.NewErrorFactory(&logger),
		Logger:     &logger,
	})
	require.NoError(t, err)

	assert.True(t, res.FilesystemPolicy)
	assert.Contains(t, res.Policy, "the project's own ignore")
	assert.NotContains(t, res.Policy, "root-level ignore that no project opted into",
		"the scan root's .snyk must not reach a project that has its own")
	assert.Equal(t, scanRoot, res.Path, "path stays the scan root; only the policy lookup is per project")
}

func TestConvertSnykSchemaFindingsToLegacy_NoPolicyInheritedFromScanRoot(t *testing.T) {
	scanRoot := t.TempDir()
	projectDir := filepath.Join(scanRoot, "proj-c")
	require.NoError(t, os.Mkdir(projectDir, 0o750))

	writePolicy(t, scanRoot, rootPolicyYAML)

	logger := zerolog.Nop()
	ctx := cmdctx.WithLogger(t.Context(), &logger)
	ctx = cmdctx.WithConfig(ctx, configuration.NewWithOpts())

	res, err := transform.ConvertSnykSchemaFindingsToLegacy(ctx, &transform.SnykSchemaToLegacyParams{
		TargetDir:  scanRoot,
		PolicyDir:  projectDir,
		ErrFactory: errors.NewErrorFactory(&logger),
		Logger:     &logger,
	})
	require.NoError(t, err)

	assert.False(t, res.FilesystemPolicy,
		"a project with no .snyk of its own reports filesystemPolicy=false, however many sit above it")
	assert.NotContains(t, res.Policy, "root-level ignore that no project opted into")
}

func TestConvertSnykSchemaFindingsToLegacy_PolicyDirDefaultsToTargetDir(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, projectPolicyYAML)

	logger := zerolog.Nop()
	ctx := cmdctx.WithLogger(t.Context(), &logger)
	ctx = cmdctx.WithConfig(ctx, configuration.NewWithOpts())

	res, err := transform.ConvertSnykSchemaFindingsToLegacy(ctx, &transform.SnykSchemaToLegacyParams{
		TargetDir:  dir,
		ErrFactory: errors.NewErrorFactory(&logger),
		Logger:     &logger,
	})
	require.NoError(t, err)

	assert.True(t, res.FilesystemPolicy)
	assert.Contains(t, res.Policy, "the project's own ignore")
}
