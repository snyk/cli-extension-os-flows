//go:build integration

package reachability_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/fileupload"
	"github.com/snyk/cli-extension-os-flows/internal/fileupload/uploadrevision"
	"github.com/snyk/cli-extension-os-flows/internal/reachability"
	"github.com/snyk/cli-extension-os-flows/internal/util"
)

func TestReachabilityScanIntegration(t *testing.T) {
	setup := util.NewIntegrationTestSetup(t)
	ffc, reachabilityClient := setupReachabilityClient(setup)

	files := []uploadrevision.LoadedFile{
		{Path: "src/main.go", Content: "package main"},
	}

	dir := util.CreateTmpFiles(t, files)

	revisionID, err := ffc.CreateRevisionFromDir(t.Context(), dir.Name(), fileupload.UploadOptions{})
	require.NoError(t, err)

	reachabilityID, err := reachabilityClient.StartReachabilityAnalysis(t.Context(), setup.Config.OrgID, revisionID)
	require.NoError(t, err)

	err = reachabilityClient.WaitForReachabilityAnalysis(t.Context(), setup.Config.OrgID, reachabilityID)
	require.NoError(t, err)
}

func setupReachabilityClient(setup *util.IntegrationTestSetup) (ffc fileupload.Client, reachabilityClient reachability.Client) {
	httpclient := setup.Client

	ffc = fileupload.NewClient(
		httpclient,
		fileupload.Config{
			BaseURL:   setup.Config.BaseURL,
			OrgID:     setup.Config.OrgID,
			IsFedRamp: false,
		},
	)

	return ffc, reachability.NewClient(httpclient, reachability.Config{
		BaseURL: setup.Config.BaseURL,
	})
}
