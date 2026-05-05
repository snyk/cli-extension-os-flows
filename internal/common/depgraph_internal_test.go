package common

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAddSCMContext(t *testing.T) {
	t.Parallel()
	nop := zerolog.Nop()

	t.Run("attaches SCM target to results without existing target", func(t *testing.T) {
		t.Parallel()
		dir := initTestGitRepo(t, "https://github.com/acme/repo.git")

		depGraphs := []RawDepGraphWithMeta{
			{Payload: []byte(`{"pkgManager":"npm"}`), NormalisedTargetFile: "package.json"},
		}

		addSCMContext(depGraphs, dir, "", &nop)

		require.NotNil(t, depGraphs[0].Target)
		var scm ScmInfo
		require.NoError(t, json.Unmarshal(depGraphs[0].Target, &scm))
		assert.Equal(t, "https://github.com/acme/repo.git", scm.RemoteURL)
		assert.Equal(t, "main", scm.Branch)
	})

	t.Run("leaves target nil when not in a git repo", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()

		depGraphs := []RawDepGraphWithMeta{
			{Payload: []byte(`{}`), NormalisedTargetFile: "pom.xml"},
		}

		addSCMContext(depGraphs, dir, "", &nop)

		assert.Nil(t, depGraphs[0].Target)
	})

	t.Run("does not overwrite existing target", func(t *testing.T) {
		t.Parallel()
		dir := initTestGitRepo(t, "https://github.com/acme/repo.git")
		existingTarget := []byte(`{"remoteUrl":"https://existing.example.com","branch":"develop"}`)

		depGraphs := []RawDepGraphWithMeta{
			{Payload: []byte(`{}`), NormalisedTargetFile: "package.json", Target: existingTarget},
		}

		addSCMContext(depGraphs, dir, "", &nop)

		assert.Equal(t, existingTarget, depGraphs[0].Target)
	})

	t.Run("fills only results missing a target in a mixed set", func(t *testing.T) {
		t.Parallel()
		dir := initTestGitRepo(t, "https://github.com/acme/mixed.git")
		existingTarget := []byte(`{"remoteUrl":"https://pre-existing.example.com","branch":"feat"}`)

		depGraphs := []RawDepGraphWithMeta{
			{Payload: []byte(`{}`), NormalisedTargetFile: "package.json", Target: existingTarget},
			{Payload: []byte(`{}`), NormalisedTargetFile: "pom.xml"},
			{Payload: []byte(`{}`), NormalisedTargetFile: "go.mod"},
		}

		addSCMContext(depGraphs, dir, "", &nop)

		assert.Equal(t, existingTarget, depGraphs[0].Target, "pre-existing target should not be overwritten")

		require.NotNil(t, depGraphs[1].Target)
		require.NotNil(t, depGraphs[2].Target)
		var scm ScmInfo
		require.NoError(t, json.Unmarshal(depGraphs[1].Target, &scm))
		assert.Equal(t, "https://github.com/acme/mixed.git", scm.RemoteURL)

		assert.Equal(t, depGraphs[1].Target, depGraphs[2].Target, "both filled results should share the same resolved target")
	})

	t.Run("uses remote-repo-url override instead of git detection", func(t *testing.T) {
		t.Parallel()
		dir := initTestGitRepo(t, "https://github.com/acme/repo.git")

		depGraphs := []RawDepGraphWithMeta{
			{Payload: []byte(`{}`), NormalisedTargetFile: "package.json"},
		}

		addSCMContext(depGraphs, dir, "https://override.example.com/repo.git", &nop)

		require.NotNil(t, depGraphs[0].Target)
		var scm ScmInfo
		require.NoError(t, json.Unmarshal(depGraphs[0].Target, &scm))
		assert.Equal(t, "https://override.example.com/repo.git", scm.RemoteURL)
	})

	t.Run("handles empty results slice without error", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()

		depGraphs := []RawDepGraphWithMeta{}

		addSCMContext(depGraphs, dir, "", &nop)

		assert.Empty(t, depGraphs)
	})

	t.Run("skips all results when every result already has a target", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		target1 := []byte(`{"remoteUrl":"a"}`)
		target2 := []byte(`{"remoteUrl":"b"}`)

		depGraphs := []RawDepGraphWithMeta{
			{Payload: []byte(`{}`), Target: target1},
			{Payload: []byte(`{}`), Target: target2},
		}

		addSCMContext(depGraphs, dir, "", &nop)

		assert.Equal(t, target1, depGraphs[0].Target)
		assert.Equal(t, target2, depGraphs[1].Target)
	})

	t.Run("attaches target to multiple results from non-git dir with override", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()

		depGraphs := []RawDepGraphWithMeta{
			{Payload: []byte(`{}`), NormalisedTargetFile: "package.json"},
			{Payload: []byte(`{}`), NormalisedTargetFile: "pom.xml"},
		}

		addSCMContext(depGraphs, dir, "https://ci.example.com/repo.git", &nop)

		for i, dg := range depGraphs {
			require.NotNil(t, dg.Target, "result %d should have target", i)
			var scm ScmInfo
			require.NoError(t, json.Unmarshal(dg.Target, &scm))
			assert.Equal(t, "https://ci.example.com/repo.git", scm.RemoteURL)
			assert.Empty(t, scm.Branch, "branch should be empty for non-git dir")
		}
	})
}

func initTestGitRepo(t *testing.T, remoteURL string) string {
	t.Helper()
	dir := t.TempDir()

	repo, err := gogit.PlainInitWithOptions(dir, &gogit.PlainInitOptions{
		InitOptions: gogit.InitOptions{
			DefaultBranch: plumbing.NewBranchReferenceName("main"),
		},
	})
	require.NoError(t, err)

	_, err = repo.CreateRemote(&gitconfig.RemoteConfig{
		Name: "origin",
		URLs: []string{remoteURL},
	})
	require.NoError(t, err)

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
