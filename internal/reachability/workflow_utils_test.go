package reachability_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/fileupload"
	"github.com/snyk/cli-extension-os-flows/internal/reachability"
)

func Test_GetReachabilityID(t *testing.T) {
	orgID := uuid.New()
	sourceDir := "."
	expectedReachabilityID := uuid.New()
	ffc := fileupload.NewFakeClient()
	frc := reachability.NewFakeClient(expectedReachabilityID)

	reachID, err := reachability.GetReachabilityID(t.Context(), orgID, sourceDir, frc, ffc)
	require.NoError(t, err)

	assert.Equal(t, expectedReachabilityID, reachID)

	assert.True(t, ffc.UploadOccurred(), "expected file upload to occur")
	assert.Equal(t, 1, ffc.GetUploadCount(), "expected exactly one upload")
}

func Test_GetReachabilityID_FailedUploadingSourceCode(t *testing.T) {
	orgID := uuid.New()
	sourceDir := "."
	expectedReachabilityID := uuid.New()
	ffc := fileupload.NewFakeClient().WithError(assert.AnError)
	frc := reachability.NewFakeClient(expectedReachabilityID)

	_, err := reachability.GetReachabilityID(t.Context(), orgID, sourceDir, frc, ffc)

	assert.ErrorContains(t, err, "failed to upload source code")
	assert.ErrorIs(t, err, assert.AnError)
	assert.Equal(t, 0, ffc.GetUploadCount(), "expected no uploads to occur")
}

func Test_GetReachabilityID_FailedToStartReachabilityAnalysis(t *testing.T) {
	orgID := uuid.New()
	sourceDir := "."
	expectedReachabilityID := uuid.New()
	ffc := fileupload.NewFakeClient()
	frc := reachability.NewFakeClient(expectedReachabilityID)
	frc.WithStartErr(assert.AnError)

	_, err := reachability.GetReachabilityID(t.Context(), orgID, sourceDir, frc, ffc)

	assert.ErrorContains(t, err, "failed to start reachability analysis")
	assert.ErrorIs(t, err, assert.AnError)
	assert.Equal(t, 1, ffc.GetUploadCount(), "expected exactly one upload")
}

func Test_GetReachabilityID_FailedToAwaitReachabilityAnalysis(t *testing.T) {
	orgID := uuid.New()
	sourceDir := "."
	expectedReachabilityID := uuid.New()
	ffc := fileupload.NewFakeClient()
	frc := reachability.NewFakeClient(expectedReachabilityID)
	frc.WithWaitErr(assert.AnError)

	_, err := reachability.GetReachabilityID(t.Context(), orgID, sourceDir, frc, ffc)

	assert.ErrorContains(t, err, "failed waiting for reachability analysis results")
	assert.ErrorIs(t, err, assert.AnError)
	assert.Equal(t, 1, ffc.GetUploadCount(), "expected exactly one upload")
}
