package util

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	"github.com/snyk/cli-extension-os-flows/internal/flags"
	"github.com/snyk/cli-extension-os-flows/pkg/localpolicy"
)

const policyFileName = ".snyk"

func resolvePolicyPath(ctx context.Context, inputDir string) (string, error) {
	cfg := cmdctx.Config(ctx)

	// take path from --policy-path
	policyPath := cfg.GetString(flags.FlagPolicyPath)
	// fallback on input directory
	if policyPath == "" {
		policyPath = inputDir
	}
	// fallback on current working directory
	if policyPath == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("failed to get current working directory: %w", err)
		}
		policyPath = cwd
	}

	// append ".snyk" if it's a directory
	policyPath, err := normalizePolicyFileName(policyPath)
	if err != nil {
		return "", err
	}

	return policyPath, nil
}

func normalizePolicyFileName(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("failed to access %q: %w", path, err)
	}

	if info.IsDir() {
		return filepath.Join(path, policyFileName), nil
	}

	return path, nil
}

// GetLocalPolicy attempts to load a local policy file from disk. If no policy
// file is found, nil is returned. An error is returned if opening or reading the
// policy file fails.
func GetLocalPolicy(ctx context.Context, inputDir string) (*localpolicy.Policy, error) {
	logger := cmdctx.Logger(ctx)

	policyPath, err := resolvePolicyPath(ctx, inputDir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve local policy file: %w", err)
	}

	fd, err := os.Open(policyPath)
	if err != nil {
		var perr *fs.PathError
		if errors.As(err, &perr) {
			logger.Info().Msg("No local policy file found.")
			//nolint:nilnil // Intentionally returning a nil policy, because none could be found.
			return nil, nil
		}
		return nil, fmt.Errorf("failed to open local policy: %w", err)
	}
	defer fd.Close()

	var p localpolicy.Policy
	if err := localpolicy.Unmarshal(fd, &p); err != nil {
		return nil, fmt.Errorf("failed to read local policy: %w", err)
	}
	return &p, nil
}
