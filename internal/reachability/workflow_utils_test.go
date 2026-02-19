package reachability_test

import (
	"path"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/apiclients/fileupload"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	"github.com/snyk/cli-extension-os-flows/internal/deeproxy"
	"github.com/snyk/cli-extension-os-flows/internal/mocks"
	"github.com/snyk/cli-extension-os-flows/internal/reachability"
	"github.com/snyk/cli-extension-os-flows/internal/util"
)

var nopLogger = zerolog.Nop()

func Test_GetReachabilityID(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mi := mocks.NewMockInstrumentation(ctrl)
	mi.EXPECT().RecordCodeUploadTime(gomock.Any()).Times(1)
	mi.EXPECT().RecordCodeAnalysisTime(gomock.Any()).Times(1)
	ctx := cmdctx.WithInstrumentation(t.Context(), mi)
	ctx = cmdctx.WithLogger(ctx, &nopLogger)

	orgID := uuid.New()
	sourceDir := util.CreateTmpFiles(t, []util.LoadedFile{
		{
			Path:    "foo.json",
			Content: `{"foo": "bar"}`,
		},
		{
			Path:    "bar.xml",
			Content: "<bar>baz</bar>",
		},
		{
			Path: "large.json",
			Size: util.Ptr(int64(1000000)),
		},
		{
			Path: "xlarge.json",
			Size: util.Ptr(int64(1048577)),
		},
		{
			Path:      "symlink.json",
			Content:   "/does/not/exist",
			IsSymlink: true,
		},
	})
	expectedReachabilityID := uuid.New()
	ffc := fileupload.NewFakeClient()
	frc := reachability.NewFakeClient(expectedReachabilityID)
	fdc := deeproxy.NewFakeClient(deeproxy.AllowList{Extensions: []string{".json"}}, nil)

	reachID, err := reachability.GetReachabilityID(ctx, orgID, sourceDir.Name(), frc, ffc, fdc)
	require.NoError(t, err)

	assert.Equal(t, expectedReachabilityID, reachID)

	uploadedPaths := ffc.GetRevisionPaths(ffc.GetLastRevisionID())

	assert.True(t, ffc.UploadOccurred(), "expected file upload to occur")
	assert.Equal(t, 1, ffc.GetUploadCount(), "expected exactly one upload")
	assert.Equal(t, 2, len(uploadedPaths), "expected 2 files to be uploaded")
	basePaths := make([]string, 2)
	for _, upath := range uploadedPaths {
		basePaths = append(basePaths, path.Base(upath))
	}
	assert.Contains(t, basePaths, "foo.json")
	assert.Contains(t, basePaths, "large.json")
}

func Test_GetReachabilityID_FailedUploadingSourceCode(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mi := mocks.NewMockInstrumentation(ctrl)
	ctx := cmdctx.WithInstrumentation(t.Context(), mi)
	ctx = cmdctx.WithLogger(ctx, &nopLogger)

	orgID := uuid.New()
	sourceDir := util.CreateTmpFiles(t, []util.LoadedFile{
		{
			Path:    "foo.json",
			Content: `{"foo": "bar"}`,
		},
		{
			Path:    "bar.xml",
			Content: "<bar>baz</bar>",
		},
		{
			Path: "large.json",
			Size: util.Ptr(int64(1000000)),
		},
		{
			Path: "xlarge.json",
			Size: util.Ptr(int64(1048577)),
		},
		{
			Path:      "symlink.json",
			Content:   "/does/not/exist",
			IsSymlink: true,
		},
	})
	expectedReachabilityID := uuid.New()
	ffc := fileupload.NewFakeClient().WithError(assert.AnError)
	frc := reachability.NewFakeClient(expectedReachabilityID)
	fdc := deeproxy.NewFakeClient(deeproxy.AllowList{Extensions: []string{".json"}}, nil)

	_, err := reachability.GetReachabilityID(ctx, orgID, sourceDir.Name(), frc, ffc, fdc)
	uploadedPaths := ffc.GetRevisionPaths(ffc.GetLastRevisionID())

	assert.ErrorContains(t, err, "failed to upload source code")
	assert.ErrorIs(t, err, assert.AnError)
	assert.Equal(t, 0, ffc.GetUploadCount(), "expected no uploads to occur")
	assert.Equal(t, 0, len(uploadedPaths), "expected no file to be uploaded")
}

func Test_GetReachabilityID_FailedToStartReachabilityAnalysis(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mi := mocks.NewMockInstrumentation(ctrl)
	ctx := cmdctx.WithInstrumentation(t.Context(), mi)
	ctx = cmdctx.WithLogger(ctx, &nopLogger)
	mi.EXPECT().RecordCodeUploadTime(gomock.Any()).Times(1)

	orgID := uuid.New()
	sourceDir := "./testdir"
	expectedReachabilityID := uuid.New()
	ffc := fileupload.NewFakeClient()
	frc := reachability.NewFakeClient(expectedReachabilityID)
	frc.WithStartErr(assert.AnError)
	fdc := deeproxy.NewFakeClient(deeproxy.AllowList{}, nil)

	_, err := reachability.GetReachabilityID(ctx, orgID, sourceDir, frc, ffc, fdc)
	uploadedPaths := ffc.GetRevisionPaths(ffc.GetLastRevisionID())

	assert.ErrorContains(t, err, "failed to start reachability analysis")
	assert.ErrorIs(t, err, assert.AnError)
	assert.Equal(t, 1, ffc.GetUploadCount(), "expected exactly one upload")
	assert.Equal(t, 0, len(uploadedPaths), "expected no file to be uploaded")
}

func Test_GetReachabilityID_FailedToAwaitReachabilityAnalysis(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mi := mocks.NewMockInstrumentation(ctrl)
	ctx := cmdctx.WithInstrumentation(t.Context(), mi)
	ctx = cmdctx.WithLogger(ctx, &nopLogger)
	mi.EXPECT().RecordCodeUploadTime(gomock.Any()).Times(1)

	orgID := uuid.New()
	sourceDir := util.CreateTmpFiles(t, []util.LoadedFile{
		{
			Path:    "foo.json",
			Content: `{"foo": "bar"}`,
		},
		{
			Path:    "bar.xml",
			Content: "<bar>baz</bar>",
		},
		{
			Path: "large.json",
			Size: util.Ptr(int64(1000000)),
		},
		{
			Path: "xlarge.json",
			Size: util.Ptr(int64(1048577)),
		},
		{
			Path:      "symlink.json",
			Content:   "/does/not/exist",
			IsSymlink: true,
		},
	})
	expectedReachabilityID := uuid.New()
	ffc := fileupload.NewFakeClient()
	frc := reachability.NewFakeClient(expectedReachabilityID)
	frc.WithWaitErr(assert.AnError)
	fdc := deeproxy.NewFakeClient(deeproxy.AllowList{Extensions: []string{".json"}}, nil)

	_, err := reachability.GetReachabilityID(ctx, orgID, sourceDir.Name(), frc, ffc, fdc)
	uploadedPaths := ffc.GetRevisionPaths(ffc.GetLastRevisionID())

	assert.ErrorContains(t, err, "failed waiting for reachability analysis results")
	assert.ErrorIs(t, err, assert.AnError)
	assert.Equal(t, 1, ffc.GetUploadCount(), "expected exactly one upload")
	assert.Equal(t, 2, len(uploadedPaths), "expected 2 files to be uploaded")
	basePaths := make([]string, 2)
	for _, upath := range uploadedPaths {
		basePaths = append(basePaths, path.Base(upath))
	}
	assert.Contains(t, basePaths, "foo.json")
	assert.Contains(t, basePaths, "large.json")
}
