package ostest_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/golang/mock/gomock"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/snyk/go-application-framework/pkg/utils"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/commands/ostest"
	"github.com/snyk/cli-extension-os-flows/internal/common"
	"github.com/snyk/cli-extension-os-flows/internal/constants"
	"github.com/snyk/cli-extension-os-flows/pkg/flags"
)

func TestOSWorkflow_DflyFlow_SendsHeadCommitAsCommitRef(t *testing.T) {
	dir := initGitRepo(t, "https://github.com/acme/repo.git")
	headSHA := commitFile(t, dir)

	scmContext := runOSTestAndCaptureScmContext(t, func(cfg configuration.Configuration) {
		cfg.Set(configuration.INPUT_DIRECTORY, []string{dir})
	})

	assert.Equal(t, &headSHA, scmContext.CommitRef)
	assert.Equal(t, "https://github.com/acme/repo.git", *scmContext.RepoUrl)
}

func TestOSWorkflow_DflyFlow_CommitIDFlagOverridesHeadCommit(t *testing.T) {
	dir := initGitRepo(t, "https://github.com/acme/repo.git")
	commitFile(t, dir)
	commitID := "0123456789abcdef0123456789abcdef01234567"

	scmContext := runOSTestAndCaptureScmContext(t, func(cfg configuration.Configuration) {
		cfg.Set(configuration.INPUT_DIRECTORY, []string{dir})
		flagSet := flags.OSTestFlagSet()
		require.NoError(t, flagSet.Parse([]string{"--commit-id", commitID}))
		require.NoError(t, cfg.AddFlagSet(flagSet))
	})

	assert.Equal(t, &commitID, scmContext.CommitRef)
}

func TestOSWorkflow_DflyFlow_OmitsCommitRefWithoutCommit(t *testing.T) {
	tests := map[string]func(t *testing.T, cfg configuration.Configuration){
		"git repository without commits": func(t *testing.T, cfg configuration.Configuration) {
			t.Helper()
			cfg.Set(configuration.INPUT_DIRECTORY, []string{initGitRepo(t, "https://github.com/acme/repo.git")})
		},
		"--remote-repo-url without a git repository": func(t *testing.T, cfg configuration.Configuration) {
			t.Helper()
			cfg.Set(configuration.INPUT_DIRECTORY, []string{t.TempDir()})
			cfg.Set(flags.FlagRemoteRepoURL, "https://github.com/acme/repo.git")
		},
	}

	for name, setup := range tests {
		t.Run(name, func(t *testing.T) {
			scmContext := runOSTestAndCaptureScmContext(t, func(cfg configuration.Configuration) {
				setup(t, cfg)
			})

			assert.Equal(t, "https://github.com/acme/repo.git", *scmContext.RepoUrl)
			assert.Nil(t, scmContext.CommitRef)
		})
	}
}

func TestOSWorkflow_SbomFlow_SendsHeadCommitAsCommitRef(t *testing.T) {
	repoDir := initGitRepo(t, "https://github.com/acme/repo.git")
	headSHA := commitFile(t, repoDir)
	sbomDir := filepath.Join(repoDir, "sboms")
	require.NoError(t, os.Mkdir(sbomDir, 0o700))
	sbomPath := filepath.Join(sbomDir, "sbom.json")
	require.NoError(t, os.WriteFile(sbomPath, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5"}`), 0o600))

	scmContext := runOSTestAndCaptureScmContext(t, func(cfg configuration.Configuration) {
		// The input directory is deliberately outside the repository: SCM context must come from where the SBOM lives.
		cfg.Set(configuration.INPUT_DIRECTORY, []string{t.TempDir()})
		cfg.Set(flags.FlagSBOM, sbomPath)
	})

	assert.Equal(t, &headSHA, scmContext.CommitRef)
	assert.Equal(t, "https://github.com/acme/repo.git", *scmContext.RepoUrl)
}

func commitFile(t *testing.T, dir string) string {
	t.Helper()

	repo, err := gogit.PlainOpen(dir)
	require.NoError(t, err)
	wt, err := repo.Worktree()
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(filepath.Join(dir, "README.md"), []byte(time.Now().String()), 0o600))
	_, err = wt.Add("README.md")
	require.NoError(t, err)

	sha, err := wt.Commit("commit", &gogit.CommitOptions{
		Author: &object.Signature{Name: "test", Email: "test@example.com", When: time.Now()},
	})
	require.NoError(t, err)

	return sha.String()
}

func runOSTestAndCaptureScmContext(t *testing.T, setup func(cfg configuration.Configuration)) *testapi.ScmContext {
	t.Helper()
	ctrl := gomock.NewController(t)

	mockAPI := newMockAPIState(t)
	t.Cleanup(mockAPI.Close)

	originalPollInterval := common.PollInterval
	common.PollInterval = testapi.MinPollInterval
	t.Cleanup(func() { common.PollInterval = originalPollInterval })

	mockEngine := mocks.NewMockEngine(ctrl)
	ictx := createMockInvocationCtxWithURL(t, ctrl, mockEngine, mockAPI.URL())
	cfg := ictx.GetConfiguration()
	cfg.Set(constants.FeatureFlagDlfyCLIRollout, true)
	cfg.Set(configuration.RAW_CMD_ARGS, []string{"test"})
	setup(cfg)

	mockIctx, ok := ictx.(*mocks.MockInvocationContext)
	require.True(t, ok)
	mockIctx.EXPECT().GetFileFilter(gomock.Any(), gomock.Any()).DoAndReturn(
		func(path string, options ...utils.FileFilterOption) *utils.FileFilter {
			return utils.NewFileFilter(path, &logger, append([]utils.FileFilterOption{utils.WithConfig(cfg)}, options...)...)
		},
	).AnyTimes()
	mockIctx.EXPECT().GetRuntimeInfo().Return(runtimeinfo.New()).AnyTimes()

	mockEngine.EXPECT().GetConfiguration().Return(cfg).AnyTimes()
	mockEngine.EXPECT().
		InvokeWithConfig(legacyWorkflowID, stdioMatcher(false)).
		Return([]workflow.Data{legacyDepGraphOutput()}, nil).
		AnyTimes()

	_, err := ostest.OSWorkflow(ictx, []workflow.Data{})
	require.NoError(t, err)

	require.Len(t, mockAPI.createTestBodies, 1)
	var body testapi.TestRequestBody
	require.NoError(t, json.Unmarshal(mockAPI.createTestBodies[0], &body))
	require.NotNil(t, body.Data.Attributes.Resources)
	resources := *body.Data.Attributes.Resources
	require.NotEmpty(t, resources)
	base, err := resources[0].AsBaseResourceCreateItem()
	require.NoError(t, err)
	upload, err := base.Resource.AsUploadResource()
	require.NoError(t, err)
	require.NotNil(t, upload.ScmContext)
	require.NotNil(t, upload.ScmContext.RepoUrl)

	return upload.ScmContext
}

func legacyDepGraphOutput() workflow.Data {
	jsonl := `{"depGraph":{"schemaVersion":"1.2.0","pkgManager":{"name":"npm"},` +
		`"pkgs":[{"id":"app@1.0.0","info":{"name":"app","version":"1.0.0"}}],` +
		`"graph":{"rootNodeId":"root","nodes":[{"nodeId":"root","pkgId":"app@1.0.0","deps":[]}]}},` +
		`"normalisedTargetFile":"package.json","targetFileFromPlugin":"package.json"}` + "\n"
	return workflow.NewData(workflow.NewTypeIdentifier(legacyWorkflowID, "depgraph"), "application/json", []byte(jsonl))
}
