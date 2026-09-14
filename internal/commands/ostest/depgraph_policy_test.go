package ostest_test

import (
	"context"
	"embed"
	"encoding/json"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sync"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	gafclientmocks "github.com/snyk/go-application-framework/pkg/apiclients/mocks"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/commands/ostest"
	"github.com/snyk/cli-extension-os-flows/internal/depgraphpayload"
	"github.com/snyk/cli-extension-os-flows/pkg/flags"
	"github.com/snyk/cli-extension-os-flows/pkg/localpolicy"
)

//go:embed all:testdata/policy-resolution
var policyCases embed.FS

const (
	resolvedCasesDir = "testdata/policy-resolution/resolved"
	rejectedCasesDir = "testdata/policy-resolution/rejected"
)

type resolvedPolicyCase struct {
	dir             string
	policyPath      string
	expectedIgnores map[string][]string
}

func Test_RunUnifiedTestFlow_ResolvesPolicyPerProject(t *testing.T) {
	t.Parallel()

	testCases := []resolvedPolicyCase{
		{
			dir:             "no-policy-anywhere",
			expectedIgnores: map[string][]string{"proj/package-lock.json": nil},
		},
		{
			dir:             "project-policy",
			expectedIgnores: map[string][]string{"proj/package-lock.json": {"policy in proj"}},
		},
		{
			dir:             "root-policy-not-inherited",
			expectedIgnores: map[string][]string{"proj/package-lock.json": nil},
		},
		{
			dir:             "project-policy-over-root",
			expectedIgnores: map[string][]string{"proj/package-lock.json": {"policy in proj"}},
		},
		{
			dir:             "policy-path-flag",
			policyPath:      "shared.snyk",
			expectedIgnores: map[string][]string{"proj/package-lock.json": {"policy at --policy-path"}},
		},
		{
			dir: "nested-projects",
			expectedIgnores: map[string][]string{
				"proj/package-lock.json":        {"policy in proj"},
				"proj/nested/package-lock.json": {"policy in proj/nested"},
			},
		},
		{
			dir:             "malformed-root-policy",
			expectedIgnores: map[string][]string{"proj/package-lock.json": nil},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.dir, func(t *testing.T) {
			t.Parallel()

			scanRoot := copyFixtureFilesToDisk(t, resolvedCasesDir, tc.dir)
			h := stubAllProjectsScan(t, scanRoot, slices.Sorted(maps.Keys(tc.expectedIgnores)), tc.policyPath)
			client, receivedIgnores := newCollectingTestClient(h.ctrl)

			_, _, err := ostest.RunUnifiedTestFlow(h.buildContext(), scanRoot, h.defaultClients(client), orgUUID, nil)

			require.NoError(t, err)
			assert.Equal(t, tc.expectedIgnores, receivedIgnores())
		})
	}
}

func Test_RunUnifiedTestFlow_RejectsUnreadablePolicy(t *testing.T) {
	t.Parallel()

	scanRoot := copyFixtureFilesToDisk(t, rejectedCasesDir, "malformed-project-policy")
	h := stubAllProjectsScan(t, scanRoot, []string{"proj/package-lock.json"}, "")
	client, _ := newCollectingTestClient(h.ctrl)

	_, _, err := ostest.RunUnifiedTestFlow(h.buildContext(), scanRoot, h.defaultClients(client), orgUUID, nil)

	require.Error(t, err)

	var catalogErr snyk_errors.Error
	require.ErrorAs(t, err, &catalogErr, "an unreadable .snyk must reach the caller as a catalog error, not unspecified prose")
	assert.Equal(t, "SNYK-POLICY-0002", catalogErr.ErrorCode)
	assert.Contains(t, catalogErr.Detail, "invalid .snyk policy")

	var pe *localpolicy.PolicyError
	assert.ErrorAs(t, err, &pe, "the underlying parse failure must stay reachable")
}

func stubAllProjectsScan(t *testing.T, scanRoot string, projects []string, policyPath string) *flowTestHarness {
	t.Helper()

	h := newFlowTestHarness(t)
	h.cfg.Set(flags.FlagAllProjects, true)
	if policyPath != "" {
		h.cfg.Set(flags.FlagPolicyPath, filepath.Join(scanRoot, policyPath))
	}
	h.instr.EXPECT().RecordOSAnalysisTime(gomock.Any()).AnyTimes()
	h.registerDepGraphsFor(projects...)

	return h
}

func copyFixtureFilesToDisk(t *testing.T, parent, dir string) string {
	t.Helper()

	root := t.TempDir()
	src := path.Join(parent, dir)

	err := fs.WalkDir(policyCases, src, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		dst := filepath.Join(root, filepath.FromSlash(rel))
		if d.IsDir() {
			return os.MkdirAll(dst, 0o750)
		}
		data, err := policyCases.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(dst, data, 0o600)
	})
	require.NoError(t, err)

	return root
}

func newCollectingTestClient(ctrl *gomock.Controller) (client *gafclientmocks.MockTestClient, collected func() map[string][]string) {
	var mu sync.Mutex
	byProject := map[string][]string{}

	client = gafclientmocks.NewMockTestClient(ctrl)
	client.EXPECT().StartTest(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, params testapi.StartTestParams) (testapi.TestHandle, error) {
			mu.Lock()
			byProject[targetFileOf(params)] = ignoreReasons(params)
			mu.Unlock()

			handle := gafclientmocks.NewMockTestHandle(ctrl)
			handle.EXPECT().Wait(gomock.Any()).Return(nil).Times(1)
			handle.EXPECT().Result().Return(newPassingTestResult(ctrl)).Times(1)
			return handle, nil
		},
	).AnyTimes()

	return client, func() map[string][]string {
		mu.Lock()
		defer mu.Unlock()
		return maps.Clone(byProject)
	}
}

func targetFileOf(params testapi.StartTestParams) string {
	subject, err := params.Subject().AsDepGraphSubjectCreate()
	if err != nil {
		return ""
	}
	var dg depgraphpayload.DepGraph
	if err := json.Unmarshal(subject.DepGraph, &dg); err != nil {
		return ""
	}
	targetFile, _ := dg.Get("targetFile")
	s, _ := targetFile.(string)
	return s
}

func ignoreReasons(params testapi.StartTestParams) []string {
	cfg := params.TestConfig()
	if cfg == nil || cfg.LocalPolicy == nil || cfg.LocalPolicy.Ignores == nil {
		return nil
	}
	reasons := make([]string, 0, len(*cfg.LocalPolicy.Ignores))
	for _, ignore := range *cfg.LocalPolicy.Ignores {
		if ignore.Reason != nil {
			reasons = append(reasons, *ignore.Reason)
		}
	}
	if len(reasons) == 0 {
		return nil
	}
	slices.Sort(reasons)
	return reasons
}
