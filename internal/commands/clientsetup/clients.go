package clientsetup

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/snyk/go-application-framework/pkg/apiclients/fileupload"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	"github.com/snyk/cli-extension-os-flows/internal/deeproxy"
	"github.com/snyk/cli-extension-os-flows/internal/reachability"
	"github.com/snyk/cli-extension-os-flows/internal/settings"
	"github.com/snyk/cli-extension-os-flows/internal/snykclient"
)

// SetupSettingsClient creates a settings.Client using the HTTP client and API URL from the context.
func SetupSettingsClient(ctx context.Context) settings.Client {
	ictx := cmdctx.Ictx(ctx)
	cfg := cmdctx.Config(ctx)
	return settings.NewClient(
		ictx.GetNetworkAccess().GetHttpClient(),
		settings.Config{BaseURL: cfg.GetString(configuration.API_URL)},
	)
}

// SetupFileUploadClient creates a fileupload.Client configured for the given org.
func SetupFileUploadClient(ctx context.Context, orgID uuid.UUID) fileupload.Client {
	ictx := cmdctx.Ictx(ctx)
	cfg := cmdctx.Config(ctx)
	return fileupload.NewClient(
		ictx.GetNetworkAccess().GetHttpClient(),
		fileupload.Config{
			BaseURL: cfg.GetString(configuration.API_URL),
			OrgID:   orgID,
		},
		fileupload.WithLogger(ictx.GetEnhancedLogger()),
	)
}

// SetupDeeproxyClient creates a deeproxy.Client using the API URL and FedRAMP config from the context.
func SetupDeeproxyClient(ctx context.Context) deeproxy.Client {
	cfg := cmdctx.Config(ctx)
	return deeproxy.NewHTTPClient(deeproxy.Config{
		BaseURL:   cfg.GetString(configuration.API_URL),
		IsFedRamp: cfg.GetBool(configuration.IS_FEDRAMP),
	})
}

// SetupReachabilityClient creates a reachability.Client using the HTTP client and API URL from the context.
func SetupReachabilityClient(ctx context.Context) reachability.Client {
	ictx := cmdctx.Ictx(ctx)
	cfg := cmdctx.Config(ctx)
	return reachability.NewClient(
		ictx.GetNetworkAccess().GetHttpClient(),
		reachability.Config{BaseURL: cfg.GetString(configuration.API_URL)},
	)
}

// SetupTestClient creates and returns a testapi.TestClient with the given poll interval.
func SetupTestClient(ctx context.Context, pollInterval time.Duration) (testapi.TestClient, error) {
	cfg := cmdctx.Config(ctx)
	ictx := cmdctx.Ictx(ctx)
	httpClient := ictx.GetNetworkAccess().GetHttpClient()
	snykClient := snykclient.NewSnykClient(httpClient, cfg.GetString(configuration.API_URL), cfg.GetString(configuration.ORGANIZATION))

	testClient, err := testapi.NewTestClient(
		snykClient.GetAPIBaseURL(),
		testapi.WithPollInterval(pollInterval),
		testapi.WithCustomHTTPClient(snykClient.GetClient()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create test client: %w", err)
	}

	return testClient, nil
}
