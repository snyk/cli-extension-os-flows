package common

import (
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/utils/git"

	"github.com/snyk/cli-extension-os-flows/pkg/flags"
)

// ScmInfo holds SCM metadata resolved from the local git repository.
type ScmInfo struct {
	RemoteURL string `json:"remoteUrl"`
	Branch    string `json:"branch"`
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
			logger.Debug().Err(err).Msg("Could not resolve git remote URL, proceeding without SCM context")
			return nil
		}
		remoteURL = detected
	}

	branch, err := git.BranchNameFromDir(inputDir)
	if err != nil {
		logger.Debug().Err(err).Msg("Could not resolve git branch, proceeding without branch in SCM context")
	}

	return &ScmInfo{
		RemoteURL: remoteURL,
		Branch:    branch,
	}
}

// ResolveScmContext builds the SCM context sent with Test API resources for inputDir, or returns
// nil when ResolveScmInfo finds no SCM info. The commit is best-effort like the branch: a HEAD
// that cannot be read is logged at Debug level and left out rather than failing the scan.
func ResolveScmContext(cfg configuration.Configuration, inputDir string, logger *zerolog.Logger) *testapi.ScmContext {
	scmInfo := ResolveScmInfo(inputDir, cfg.GetString(flags.FlagRemoteRepoURL), logger)
	if scmInfo == nil {
		return nil
	}

	scmCtx := &testapi.ScmContext{
		RepoUrl: &scmInfo.RemoteURL,
		Branch:  &scmInfo.Branch,
	}

	// Without --commit-id, the commit comes from the scanned checkout even when --remote-repo-url overrides the URL:
	// the override only names the project, while the code being tested is the local checkout.
	commitID := cfg.GetString(flags.FlagCommitID)
	if commitID == "" {
		var err error
		commitID, err = git.HeadCommitHashFromDir(inputDir)
		if err != nil {
			logger.Debug().Err(err).Msg("Could not resolve git commit, proceeding without commit in SCM context")
		}
	}
	if commitID != "" {
		scmCtx.CommitRef = &commitID
	}

	return scmCtx
}

// HasScmContext reports whether every input directory has SCM info, either from its
// git remote or from remoteURLOverride. The dfly flow identifies the project by that
// context, so `test` and `monitor` only route to it when every directory has one.
func HasScmContext(inputDirs []string, remoteURLOverride string, logger *zerolog.Logger) bool {
	for _, inputDir := range inputDirs {
		if ResolveScmInfo(inputDir, remoteURLOverride, logger) == nil {
			return false
		}
	}

	return true
}
