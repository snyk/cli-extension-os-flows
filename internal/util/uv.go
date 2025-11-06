package util

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/rs/zerolog"

	"github.com/snyk/cli-extension-os-flows/internal/constants"
)

// HasUvLockFile checks if the specified directory contains a uv.lock file.
func HasUvLockFile(dir string, logger *zerolog.Logger) bool {
	uvLockPath := filepath.Join(dir, constants.UvLockFileName)
	_, err := os.Stat(uvLockPath)
	if err == nil {
		return true
	}

	if !errors.Is(err, os.ErrNotExist) && logger != nil {
		logger.Debug().
			Err(err).
			Str("path", uvLockPath).
			Msg("Error checking for uv.lock file")
	}

	return false
}

// HasNestedUvLockFile checks if any of the input directories contains a uv.lock file.
func HasNestedUvLockFile(inputDirs []string, logger *zerolog.Logger) bool {
	for _, inputDir := range inputDirs {
		if HasUvLockFile(inputDir, logger) {
			return true
		}
	}
	return false
}
