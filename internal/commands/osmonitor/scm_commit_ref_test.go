package osmonitor_test

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
	"github.com/snyk/go-application-framework/pkg/utils"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/commands/osmonitor"
	"github.com/snyk/cli-extension-os-flows/internal/common"
	"github.com/snyk/cli-extension-os-flows/internal/constants"
	"github.com/snyk/cli-extension-os-flows/internal/util/fakeapi"
	"github.com/snyk/cli-extension-os-flows/pkg/flags"
)

func TestOSWorkflow_DflyFlow_MonitorSendsHeadCommitAsCommitRef(t *testing.T) {
	dir := initGitRepo(t, "https://github.com/acme/repo.git")
	headSHA := commitFile(t, dir)

	scmContext := runOSMonitorAndCaptureScmContext(t, func(cfg configuration.Configuration) {
		cfg.Set(configuration.INPUT_DIRECTORY, []string{dir})
	})

	require.NotNil(t, scmContext.CommitRef)
	assert.Equal(t, headSHA, *scmContext.CommitRef)
	assert.Equal(t, "https://github.com/acme/repo.git", *scmContext.RepoUrl)
}

func TestOSWorkflow_DflyFlow_MonitorCommitIDFlagOverridesHeadCommit(t *testing.T) {
	dir := initGitRepo(t, "https://github.com/acme/repo.git")
	headSHA := commitFile(t, dir)
	commitID := "0123456789abcdef0123456789abcdef01234567"
	require.NotEqual(t, headSHA, commitID)

	scmContext := runOSMonitorAndCaptureScmContext(t, func(cfg configuration.Configuration) {
		cfg.Set(configuration.INPUT_DIRECTORY, []string{dir})
		flagSet := flags.OSMonitorFlagSet()
		require.NoError(t, flagSet.Parse([]string{"--commit-id", commitID}))
		require.NoError(t, cfg.AddFlagSet(flagSet))
	})

	require.NotNil(t, scmContext.CommitRef)
	assert.Equal(t, commitID, *scmContext.CommitRef)
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

func runOSMonitorAndCaptureScmContext(t *testing.T, setup func(cfg configuration.Configuration)) *testapi.ScmContext {
	t.Helper()
	ctrl := gomock.NewController(t)

	fakeAPI := fakeapi.NewTestAPIServer(t)
	t.Cleanup(fakeAPI.Close)

	originalPollInterval := common.PollInterval
	common.PollInterval = testapi.MinPollInterval
	t.Cleanup(func() { common.PollInterval = originalPollInterval })

	mockEngine := createMockEngine(ctrl)
	mockIctx := createMockInvocationCtxWithURL(t, ctrl, mockEngine)
	cfg := mockIctx.GetConfiguration()
	cfg.Set(configuration.API_URL, fakeAPI.URL())
	cfg.Set(constants.FeatureFlagDlfyCLIRollout, true)
	cfg.Set(configuration.RAW_CMD_ARGS, []string{"monitor"})
	setup(cfg)

	mockIctx.EXPECT().GetFileFilter(gomock.Any(), gomock.Any()).DoAndReturn(
		func(path string, options ...utils.FileFilterOption) *utils.FileFilter {
			return utils.NewFileFilter(path, &nopLogger, append([]utils.FileFilterOption{utils.WithConfig(cfg)}, options...)...)
		},
	).AnyTimes()
	mockEngine.EXPECT().GetConfiguration().Return(cfg).AnyTimes()
	mockEngine.EXPECT().
		InvokeWithConfig(workflow.NewWorkflowIdentifier("legacycli"), gomock.Any()).
		Return([]workflow.Data{legacyDepGraphOutput()}, nil).
		AnyTimes()

	_, err := osmonitor.OSWorkflow(mockIctx, []workflow.Data{})
	require.NoError(t, err)

	createTestBodies := fakeAPI.CreateTestBodies()
	require.Len(t, createTestBodies, 1)
	var body testapi.TestRequestBody
	require.NoError(t, json.Unmarshal(createTestBodies[0], &body))
	require.NotNil(t, body.Data.Attributes.Config)
	require.NotNil(t, body.Data.Attributes.Config.Monitor)
	require.True(t, *body.Data.Attributes.Config.Monitor)
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
	return workflow.NewData(workflow.NewTypeIdentifier(workflow.NewWorkflowIdentifier("legacycli"), "depgraph"), "application/json", []byte(jsonl))
}
