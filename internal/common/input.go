package common

import (
	"fmt"
	"os"

	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/cli-extension-os-flows/pkg/flags"
)

// GetInputDirectories resolves all input directories from configuration,
// falling back to the current working directory if none are set.
func GetInputDirectories(cfg configuration.Configuration) ([]string, error) {
	inputDirs := cfg.GetStringSlice(configuration.INPUT_DIRECTORY)
	if len(inputDirs) > 0 {
		return inputDirs, nil
	}

	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("failed to determine working directory: %w", err)
	}
	return []string{cwd}, nil
}

// GetSourceDir resolves the source directory from configuration, falling back
// to the given inputDir when --source-dir is not set.
func GetSourceDir(cfg configuration.Configuration, inputDir string) string {
	sourceDir := cfg.GetString(flags.FlagSourceDir)
	if sourceDir != "" {
		return sourceDir
	}
	return inputDir
}
