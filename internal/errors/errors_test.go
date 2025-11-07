package errors_test

import (
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
		err := errorFactory.NewInvalidLegacyFlagError("reachability")
		var catalogErr snyk_errors.Error
		require.ErrorAs(t, err, &catalogErr)
		assert.Equal(t, "The option --reachability cannot be used with the legacy CLI.", catalogErr.Detail)
	})

	t.Run("two flags", func(t *testing.T) {
		err := errorFactory.NewInvalidLegacyFlagError("reachability", "unmanaged")

		var catalogErr snyk_errors.Error
		require.ErrorAs(t, err, &catalogErr)
		assert.Equal(t, "The options --reachability, --unmanaged cannot be used together.", catalogErr.Detail)
	})

	t.Run("three flags", func(t *testing.T) {
		err := errorFactory.NewInvalidLegacyFlagError("reachability", "unmanaged", "all-projects")
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
