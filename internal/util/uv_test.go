package util_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/constants"
	"github.com/snyk/cli-extension-os-flows/internal/util"
)

func TestHasUvLockFile(t *testing.T) {
	t.Parallel()
	nopLogger := zerolog.Nop()

	t.Run("returns true when uv.lock exists", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		uvLockPath := filepath.Join(dir, constants.UvLockFileName)
		err := os.WriteFile(uvLockPath, []byte("# test"), 0o600)
		require.NoError(t, err)

		result := util.HasUvLockFile(dir, &nopLogger)
		assert.True(t, result)
	})

	t.Run("returns false when uv.lock does not exist", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()

		result := util.HasUvLockFile(dir, &nopLogger)
		assert.False(t, result)
	})

	t.Run("returns false when directory does not exist", func(t *testing.T) {
		t.Parallel()
		dir := filepath.Join(t.TempDir(), "nonexistent")

		result := util.HasUvLockFile(dir, &nopLogger)
		assert.False(t, result)
	})

	t.Run("works with nil logger", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		uvLockPath := filepath.Join(dir, constants.UvLockFileName)
		err := os.WriteFile(uvLockPath, []byte("# test"), 0o600)
		require.NoError(t, err)

		result := util.HasUvLockFile(dir, nil)
		assert.True(t, result)
	})
}

func TestHasUvLockFileInAnyDir(t *testing.T) {
	t.Parallel()
	nopLogger := zerolog.Nop()

	t.Run("returns true when first directory has uv.lock", func(t *testing.T) {
		t.Parallel()
		dir1 := t.TempDir()
		dir2 := t.TempDir()

		uvLockPath := filepath.Join(dir1, constants.UvLockFileName)
		err := os.WriteFile(uvLockPath, []byte("# test"), 0o600)
		require.NoError(t, err)

		result := util.HasUvLockFileInAnyDir([]string{dir1, dir2}, &nopLogger)
		assert.True(t, result)
	})

	t.Run("returns true when second directory has uv.lock", func(t *testing.T) {
		t.Parallel()
		dir1 := t.TempDir()
		dir2 := t.TempDir()

		uvLockPath := filepath.Join(dir2, constants.UvLockFileName)
		err := os.WriteFile(uvLockPath, []byte("# test"), 0o600)
		require.NoError(t, err)

		result := util.HasUvLockFileInAnyDir([]string{dir1, dir2}, &nopLogger)
		assert.True(t, result)
	})

	t.Run("returns true when multiple directories have uv.lock", func(t *testing.T) {
		t.Parallel()
		dir1 := t.TempDir()
		dir2 := t.TempDir()

		uvLockPath1 := filepath.Join(dir1, constants.UvLockFileName)
		err := os.WriteFile(uvLockPath1, []byte("# test"), 0o600)
		require.NoError(t, err)

		uvLockPath2 := filepath.Join(dir2, constants.UvLockFileName)
		err = os.WriteFile(uvLockPath2, []byte("# test"), 0o600)
		require.NoError(t, err)

		result := util.HasUvLockFileInAnyDir([]string{dir1, dir2}, &nopLogger)
		assert.True(t, result)
	})

	t.Run("returns false when no directories have uv.lock", func(t *testing.T) {
		t.Parallel()
		dir1 := t.TempDir()
		dir2 := t.TempDir()

		result := util.HasUvLockFileInAnyDir([]string{dir1, dir2}, &nopLogger)
		assert.False(t, result)
	})

	t.Run("returns false for empty directory list", func(t *testing.T) {
		t.Parallel()

		result := util.HasUvLockFileInAnyDir([]string{}, &nopLogger)
		assert.False(t, result)
	})

	t.Run("handles mix of existing and non-existing directories", func(t *testing.T) {
		t.Parallel()
		dir1 := t.TempDir()
		nonExistentDir := filepath.Join(t.TempDir(), "nonexistent")

		uvLockPath := filepath.Join(dir1, constants.UvLockFileName)
		err := os.WriteFile(uvLockPath, []byte("# test"), 0o600)
		require.NoError(t, err)

		result := util.HasUvLockFileInAnyDir([]string{nonExistentDir, dir1}, &nopLogger)
		assert.True(t, result)
	})
}
