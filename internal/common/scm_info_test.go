package common_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/utils/git"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/common"
)

func TestResolveScmInfo(t *testing.T) {
	nop := zerolog.Nop()

	t.Run("returns remote url and branch from git repo", func(t *testing.T) {
		dir := initGitRepo(t, "https://github.com/acme/repo.git")

		info := common.ResolveScmInfo(dir, "", &nop)

		require.NotNil(t, info)
		assert.Equal(t, "https://github.com/acme/repo.git", info.RemoteURL)
		assert.Equal(t, "main", info.Branch)
	})

	t.Run("override replaces detected remote url", func(t *testing.T) {
		dir := initGitRepo(t, "https://github.com/acme/repo.git")

		info := common.ResolveScmInfo(dir, "https://custom.example.com/override.git", &nop)

		require.NotNil(t, info)
		assert.Equal(t, "https://custom.example.com/override.git", info.RemoteURL)
	})

	t.Run("returns nil for non-git directory", func(t *testing.T) {
		dir := t.TempDir()

		info := common.ResolveScmInfo(dir, "", &nop)

		assert.Nil(t, info)
	})

	t.Run("override with non-git directory still returns info", func(t *testing.T) {
		dir := t.TempDir()

		info := common.ResolveScmInfo(dir, "https://override.example.com/repo.git", &nop)

		require.NotNil(t, info)
		assert.Equal(t, "https://override.example.com/repo.git", info.RemoteURL)
		assert.Empty(t, info.Branch)
	})
}

func initGitRepo(t *testing.T, remoteURL string) string {
	t.Helper()
	dir := t.TempDir()

	repo, err := gogit.PlainInitWithOptions(dir, &gogit.PlainInitOptions{
		InitOptions: gogit.InitOptions{
			DefaultBranch: plumbing.NewBranchReferenceName("main"),
		},
	})
	require.NoError(t, err)

	_, err = repo.CreateRemote(&config.RemoteConfig{
		Name: "origin",
		URLs: []string{remoteURL},
	})
	require.NoError(t, err)

	// Create an initial commit so HEAD exists with a branch ref.
	wt, err := repo.Worktree()
	require.NoError(t, err)
	f, err := os.CreateTemp(dir, "init")
	require.NoError(t, err)
	f.Close()
	_, err = wt.Add(f.Name()[len(dir)+1:])
	require.NoError(t, err)
	_, err = wt.Commit("init", &gogit.CommitOptions{
		Author: &object.Signature{Name: "test", Email: "test@test.com", When: time.Now()},
	})
	require.NoError(t, err)

	return dir
}

func TestResolveScmContext(t *testing.T) {
	nop := zerolog.Nop()

	t.Run("omits commit when HEAD cannot be read", func(t *testing.T) {
		dir := initGitRepo(t, "https://github.com/acme/repo.git")
		require.NoError(t, os.WriteFile(filepath.Join(dir, ".git", "HEAD"), []byte("ref: refs/heads/main\x00"), 0o600))
		_, headErr := git.HeadCommitHashFromDir(dir)
		require.Error(t, headErr)

		scmCtx := common.ResolveScmContext(configuration.NewWithOpts(), dir, &nop)

		require.NotNil(t, scmCtx)
		assert.Equal(t, "https://github.com/acme/repo.git", *scmCtx.RepoUrl)
		assert.Nil(t, scmCtx.CommitRef)
	})
}
