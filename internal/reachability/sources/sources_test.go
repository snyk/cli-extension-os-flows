package sources_test

import (
	"io"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/reachability/sources"
)

func nopLogger() *zerolog.Logger {
	l := zerolog.New(io.Discard)
	return &l
}

func TestHasSupportedSources_EmptyDir_ReturnsFalse(t *testing.T) {
	dir := t.TempDir()

	got, err := sources.HasSupportedSources(dir, nopLogger())

	require.NoError(t, err)
	assert.False(t, got)
}
