package ostest

import (
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/utils/git"
)

// ScmInfo holds SCM metadata resolved from the local git repository.
type ScmInfo struct {
	RemoteURL string
	Branch    string
}

// ResolveScmInfo resolves SCM info from the git repository at inputDir.
// If remoteURLOverride is non-empty it takes precedence over the detected URL.
// Both lookups are best-effort: failures are logged at Debug level and never propagated.
// Returns nil when no remote URL can be determined (no override and git lookup fails).
func ResolveScmInfo(inputDir, remoteURLOverride string, logger *zerolog.Logger) *ScmInfo {
	remoteURL := remoteURLOverride
	if remoteURL == "" {
		detected, err := git.GetRemoteUrl(inputDir)
		if err != nil {
			logger.Warn().Err(err).Msg("Could not resolve git remote URL, proceeding without SCM context")
			return nil
		}
		remoteURL = detected
	}

	branch, err := git.BranchNameFromDir(inputDir)
	if err != nil {
		logger.Warn().Err(err).Msg("Could not resolve git branch, proceeding without branch in SCM context")
	}

	return &ScmInfo{
		RemoteURL: remoteURL,
		Branch:    branch,
	}
}
