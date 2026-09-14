package errors_test

import (
	goerrors "errors"
	"testing"

	"github.com/snyk/cli-extension-os-flows/internal/errors"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	snyk_errors "github.com/snyk/error-catalog-golang-public/snyk_errors"
)

func TestNewInvalidLegacyFlagError(t *testing.T) {
	logger := zerolog.Nop()
	errorFactory := errors.NewErrorFactory(&logger)

	t.Run("single flag", func(t *testing.T) {
		err := errorFactory.NewInvalidLegacyFlagError("--reachability")
		var catalogErr snyk_errors.Error
		require.ErrorAs(t, err, &catalogErr)
		assert.Equal(t, "The option --reachability cannot be used in this way.", catalogErr.Detail)
	})

	t.Run("two flags", func(t *testing.T) {
		err := errorFactory.NewInvalidLegacyFlagError("--reachability", "--unmanaged")

		var catalogErr snyk_errors.Error
		require.ErrorAs(t, err, &catalogErr)
		assert.Equal(t, "The options --reachability, --unmanaged cannot be used together.", catalogErr.Detail)
	})

	t.Run("three flags", func(t *testing.T) {
		err := errorFactory.NewInvalidLegacyFlagError("--reachability", "--unmanaged", "--all-projects")
		var catalogErr snyk_errors.Error
		require.ErrorAs(t, err, &catalogErr)
		assert.Equal(t, "The options --reachability, --unmanaged, --all-projects cannot be used together.", catalogErr.Detail)
	})

	t.Run("no flags", func(t *testing.T) {
		err := errorFactory.NewInvalidLegacyFlagError()
		var catalogErr snyk_errors.Error
		require.ErrorAs(t, err, &catalogErr)
		assert.Equal(t, "An internal error occurred while validating command-line flags.", catalogErr.Detail)
	})
}

func TestNewInvalidPolicyFileError(t *testing.T) {
	cause := goerrors.New("invalid .snyk policy: yaml: line 3: found character that cannot start any token")
	err := errors.NewInvalidPolicyFileError("/repo/.snyk", cause)

	var catalogErr snyk_errors.Error
	require.ErrorAs(t, err, &catalogErr)

	assert.Equal(t, "SNYK-POLICY-0002", catalogErr.ErrorCode)
	assert.Equal(t, "error", catalogErr.Level)
	assert.Contains(t, catalogErr.Detail, "/repo/.snyk")
	assert.Contains(t, catalogErr.Detail, "line 3")
	assert.ErrorIs(t, err, cause, "the parse failure must stay reachable as the cause")

	assert.NotContains(t, catalogErr.Detail, "correct the file")
	assert.Contains(t, catalogErr.Description, "Correct the file and try again.")
}

func TestNewUnsupportedFailOnValueError(t *testing.T) {
	logger := zerolog.Nop()
	errorFactory := errors.NewErrorFactory(&logger)

	err := errorFactory.NewUnsupportedFailOnValueError("invalid-value")
	var catalogErr snyk_errors.Error
	require.ErrorAs(t, err, &catalogErr)
	assert.Equal(t, "Unsupported value 'invalid-value' for --fail-on flag. Supported values are: 'all', 'upgradable'.", catalogErr.Detail)
}

func TestNewInvalidSourceDirError(t *testing.T) {
	logger := zerolog.Nop()
	errorFactory := errors.NewErrorFactory(&logger)

	err := errorFactory.NewInvalidSourceDirError("/path/to/nonexistent")
	var catalogErr snyk_errors.Error
	require.ErrorAs(t, err, &catalogErr)
	assert.Equal(t, "The provided --source-dir path '/path/to/nonexistent' does not exist.", catalogErr.Detail)
	assert.Equal(t, "SNYK-CLI-0004", catalogErr.ErrorCode)
}

func TestNewSourceDirIsNotADirectoryError(t *testing.T) {
	logger := zerolog.Nop()
	errorFactory := errors.NewErrorFactory(&logger)

	err := errorFactory.NewSourceDirIsNotADirectoryError("/path/to/file.txt")
	var catalogErr snyk_errors.Error
	require.ErrorAs(t, err, &catalogErr)
	assert.Equal(t, "The provided --source-dir path '/path/to/file.txt' is not a directory.", catalogErr.Detail)
	assert.Equal(t, "SNYK-CLI-0004", catalogErr.ErrorCode)
}
