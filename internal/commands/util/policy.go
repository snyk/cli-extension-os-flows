package util

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"

	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	"github.com/snyk/cli-extension-os-flows/internal/flags"
	"github.com/snyk/cli-extension-os-flows/pkg/localpolicy"
)

const policyFileName = ".snyk"

// ResolvePolicyFile resolves to a snyk policy file. The given path can either point at
// a policy file or a directory which contains a .snyk file. If no policy
// is found at the given location, an error is returned.
func ResolvePolicyFile(ctx context.Context) (*os.File, error) {
	cfg := cmdctx.Config(ctx)
	dirOrFile := cfg.GetString(flags.FlagPolicyPath)
	if dirOrFile == "" {
		dirOrFile = cfg.GetString(configuration.INPUT_DIRECTORY)
	}
	if dirOrFile == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("failed to get current working directory: %w", err)
		}
		dirOrFile = cwd
	}

	// if a directory was given, add the expected policy file name.
	info, err := os.Stat(dirOrFile)
	if err != nil {
		return nil, fmt.Errorf("failed to find %s file: %w", policyFileName, err)
	}
	if info.IsDir() {
		dirOrFile = path.Join(dirOrFile, policyFileName)
	}

	fd, err := os.Open(dirOrFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s file: %w", policyFileName, err)
	}

	return fd, nil
}

// GetLocalPolicy attempts to load a local policy file from disk. If no policy
// file is found, nil is returned. An error is returned if opening or reading the
// policy file fails.
func GetLocalPolicy(ctx context.Context) (*localpolicy.Policy, error) {
	logger := cmdctx.Logger(ctx)

	policyFile, err := ResolvePolicyFile(ctx)
	if err != nil {
		var perr *fs.PathError
		if errors.As(err, &perr) {
			logger.Info().Msgf("No %s file found.", policyFileName)
			//nolint:nilnil // Intentionally returning a nil policy, because none could be found.
			return nil, nil
		}
		return nil, fmt.Errorf("failed to open %s file: %w", policyFileName, err)
	}
	defer policyFile.Close()

	var p localpolicy.Policy
	if err := localpolicy.Unmarshal(policyFile, &p); err != nil {
		return nil, fmt.Errorf("failed to read %s file: %w", policyFileName, err)
	}
	return &p, nil
}
