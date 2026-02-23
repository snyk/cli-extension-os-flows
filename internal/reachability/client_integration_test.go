//go:build integration

package reachability_test

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/apiclients/fileupload"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	"github.com/snyk/cli-extension-os-flows/internal/deeproxy"
	"github.com/snyk/cli-extension-os-flows/internal/mocks"
	"github.com/snyk/cli-extension-os-flows/internal/reachability"
	"github.com/snyk/cli-extension-os-flows/internal/util"
)

func TestReachabilityScanIntegration(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	setup := util.NewIntegrationTestSetup(t)
	ffc, dc, reachabilityClient := setupReachabilityClient(setup)

	files := []util.LoadedFile{
		{Path: "src/main.go", Content: "package main"},
	}

	dir := util.CreateTmpFiles(t, files)
	logger := zerolog.Nop()
	mi := mocks.NewMockInstrumentation(ctrl)
	mi.EXPECT().RecordCodeUploadTime(gomock.Any()).Times(1)
	ctx := cmdctx.WithLogger(t.Context(), &logger)
	ctx = cmdctx.WithInstrumentation(ctx, mi)

	res, err := reachability.UploadSourceCode(ctx, setup.Config.OrgID, ffc, dc, dir.Name())
	require.NoError(t, err)

	reachabilityID, err := reachabilityClient.StartReachabilityAnalysis(t.Context(), setup.Config.OrgID, res.RevisionID)
	require.NoError(t, err)

	err = reachabilityClient.WaitForReachabilityAnalysis(t.Context(), setup.Config.OrgID, reachabilityID)
	require.NoError(t, err)
}

func setupReachabilityClient(setup *util.IntegrationTestSetup) (ffc fileupload.Client, dc deeproxy.Client, reachabilityClient reachability.Client) {
	httpclient := setup.Client

	ffc = fileupload.NewClient(
		httpclient,
		fileupload.Config{
			BaseURL: setup.Config.BaseURL,
			OrgID:   setup.Config.OrgID,
		},
	)

	dc = deeproxy.NewHTTPClient(deeproxy.Config{
		BaseURL:   setup.Config.BaseURL,
		IsFedRamp: false,
	}, deeproxy.WithHTTPClient(httpclient))

	return ffc, dc, reachability.NewClient(httpclient, reachability.Config{
		BaseURL: setup.Config.BaseURL,
	})
}
