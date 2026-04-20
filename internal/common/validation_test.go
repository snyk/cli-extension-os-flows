package common_test

import (
	"os"
	"testing"

	"github.com/rs/zerolog"
	snyk_errors "github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/common"
	"github.com/snyk/cli-extension-os-flows/internal/errors"
)

func Test_ValidateSourceDir(t *testing.T) {
	t.Parallel()

	logger := zerolog.Nop()
	errFactory := errors.NewErrorFactory(&logger)

	t.Run("should return no error when source dir exists", func(t *testing.T) {
		t.Parallel()
		tempDir := t.TempDir()

		err := common.ValidateSourceDir(tempDir, errFactory)
		require.NoError(t, err)
	})

	t.Run("should return InvalidFlagOptionError when source dir does not exist", func(t *testing.T) {
		t.Parallel()
		nonExistentDir := "/path/to/nonexistent/directory"

		err := common.ValidateSourceDir(nonExistentDir, errFactory)
		require.Error(t, err)

		var catalogErr snyk_errors.Error
		require.ErrorAs(t, err, &catalogErr)
		assert.Equal(t, "SNYK-CLI-0004", catalogErr.ErrorCode)
		assert.Contains(t, catalogErr.Detail, "The provided --source-dir path")
		assert.Contains(t, catalogErr.Detail, nonExistentDir)
	})

	t.Run("should return InvalidFlagOptionError for relative nonexistent path", func(t *testing.T) {
		t.Parallel()
		nonExistentDir := "nonexistent-relative-dir"

		err := common.ValidateSourceDir(nonExistentDir, errFactory)
		require.Error(t, err)

		var catalogErr snyk_errors.Error
		require.ErrorAs(t, err, &catalogErr)
		assert.Equal(t, "SNYK-CLI-0004", catalogErr.ErrorCode)
		assert.Contains(t, catalogErr.Detail, nonExistentDir)
	})

	t.Run("should return InvalidFlagOptionError when source dir is a file", func(t *testing.T) {
		t.Parallel()
		tempFile, err := os.CreateTemp("", "test-file-*.txt")
		require.NoError(t, err)
		defer os.Remove(tempFile.Name())
		tempFile.Close()

		err = common.ValidateSourceDir(tempFile.Name(), errFactory)
		require.Error(t, err)

		var catalogErr snyk_errors.Error
		require.ErrorAs(t, err, &catalogErr)
		assert.Equal(t, "SNYK-CLI-0004", catalogErr.ErrorCode)
		assert.Contains(t, catalogErr.Detail, "is not a directory")
		assert.Contains(t, catalogErr.Detail, tempFile.Name())
	})
}
