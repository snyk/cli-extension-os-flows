package reachability_test

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	"github.com/snyk/cli-extension-os-flows/internal/fileupload"
	"github.com/snyk/cli-extension-os-flows/internal/mocks"
	"github.com/snyk/cli-extension-os-flows/internal/reachability"
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
	sourceDir := "."
	expectedReachabilityID := uuid.New()
	ffc := fileupload.NewFakeClient()
	frc := reachability.NewFakeClient(expectedReachabilityID)

	reachID, err := reachability.GetReachabilityID(ctx, orgID, sourceDir, frc, ffc)
	require.NoError(t, err)

	assert.Equal(t, expectedReachabilityID, reachID)

	assert.True(t, ffc.UploadOccurred(), "expected file upload to occur")
	assert.Equal(t, 1, ffc.GetUploadCount(), "expected exactly one upload")
}

func Test_GetReachabilityID_FailedUploadingSourceCode(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mi := mocks.NewMockInstrumentation(ctrl)
	ctx := cmdctx.WithInstrumentation(t.Context(), mi)
	ctx = cmdctx.WithLogger(ctx, &nopLogger)

	orgID := uuid.New()
	sourceDir := "."
	expectedReachabilityID := uuid.New()
	ffc := fileupload.NewFakeClient().WithError(assert.AnError)
	frc := reachability.NewFakeClient(expectedReachabilityID)

	_, err := reachability.GetReachabilityID(ctx, orgID, sourceDir, frc, ffc)

	assert.ErrorContains(t, err, "failed to upload source code")
	assert.ErrorIs(t, err, assert.AnError)
	assert.Equal(t, 0, ffc.GetUploadCount(), "expected no uploads to occur")
}

func Test_GetReachabilityID_FailedToStartReachabilityAnalysis(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mi := mocks.NewMockInstrumentation(ctrl)
	ctx := cmdctx.WithInstrumentation(t.Context(), mi)
	ctx = cmdctx.WithLogger(ctx, &nopLogger)
	mi.EXPECT().RecordCodeUploadTime(gomock.Any()).Times(1)

	orgID := uuid.New()
	sourceDir := "."
	expectedReachabilityID := uuid.New()
	ffc := fileupload.NewFakeClient()
	frc := reachability.NewFakeClient(expectedReachabilityID)
	frc.WithStartErr(assert.AnError)

	_, err := reachability.GetReachabilityID(ctx, orgID, sourceDir, frc, ffc)

	assert.ErrorContains(t, err, "failed to start reachability analysis")
	assert.ErrorIs(t, err, assert.AnError)
	assert.Equal(t, 1, ffc.GetUploadCount(), "expected exactly one upload")
}

func Test_GetReachabilityID_FailedToAwaitReachabilityAnalysis(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mi := mocks.NewMockInstrumentation(ctrl)
	ctx := cmdctx.WithInstrumentation(t.Context(), mi)
	ctx = cmdctx.WithLogger(ctx, &nopLogger)
	mi.EXPECT().RecordCodeUploadTime(gomock.Any()).Times(1)

	orgID := uuid.New()
	sourceDir := "."
	expectedReachabilityID := uuid.New()
	ffc := fileupload.NewFakeClient()
	frc := reachability.NewFakeClient(expectedReachabilityID)
	frc.WithWaitErr(assert.AnError)

	_, err := reachability.GetReachabilityID(ctx, orgID, sourceDir, frc, ffc)

	assert.ErrorContains(t, err, "failed waiting for reachability analysis results")
	assert.ErrorIs(t, err, assert.AnError)
	assert.Equal(t, 1, ffc.GetUploadCount(), "expected exactly one upload")
}
