//go:build integration

package reachability_test

import (
	"net/http"
	"testing"

	"github.com/rs/zerolog"
	codeclient "github.com/snyk/code-client-go"
	codeclienthttp "github.com/snyk/code-client-go/http"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/bundlestore"
	"github.com/snyk/cli-extension-os-flows/internal/fileupload/uploadrevision"
	"github.com/snyk/cli-extension-os-flows/internal/reachability"
	"github.com/snyk/cli-extension-os-flows/internal/util"
)

func TestReachabilityScanIntegration(t *testing.T) {
	setup := util.NewIntegrationTestSetup(t)
	bsClient, reachabilityClient := setupReachabilityClient(setup)

	files := []uploadrevision.LoadedFile{
		{Path: "src/main.go", Content: "package main"},
	}

	dir := util.CreateTmpFiles(t, files)

	bundleHash, err := bsClient.UploadSourceCode(t.Context(), dir.Name())
	require.NoError(t, err)

	reachabilityID, err := reachabilityClient.StartReachabilityAnalysis(t.Context(), setup.Config.OrgID, bundleHash)
	require.NoError(t, err)

	err = reachabilityClient.WaitForReachabilityAnalysis(t.Context(), setup.Config.OrgID, reachabilityID)
	require.NoError(t, err)
}

func setupReachabilityClient(setup *util.IntegrationTestSetup) (bsClient bundlestore.Client, reachabilityClient reachability.Client) {
	httpclient := setup.Client
	httpCodeClient := codeclienthttp.NewHTTPClient(
		func() *http.Client { return httpclient },
	)

	cfg := configuration.New()
	cfg.Set(configuration.API_URL, setup.Config.BaseURL)
	codeScannerConfig := bundlestore.CodeClientConfig{
		LocalConfiguration: cfg,
	}

	cScanner := codeclient.NewCodeScanner(
		&codeScannerConfig,
		httpCodeClient,
	)

	nopLogger := zerolog.Nop()
	bsClient = bundlestore.NewClient(httpclient, codeScannerConfig, cScanner, &nopLogger)

	return bsClient, reachability.NewClient(httpclient, reachability.Config{
		BaseURL: setup.Config.BaseURL,
	})
}
