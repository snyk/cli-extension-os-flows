///go:build integration

package util

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"testing"

	"github.com/google/uuid"
)

// TestConfig holds configuration for integration tests.
type TestConfig struct {
	BaseURL  string
	OrgID    uuid.UUID
	APIToken string
}

// IntegrationTestSetup provides utilities for integration tests.
type IntegrationTestSetup struct {
	Config TestConfig
	Client *http.Client
}

// NewIntegrationTestSetup creates a new integration test setup with validation.
func NewIntegrationTestSetup(t *testing.T) *IntegrationTestSetup {
	t.Helper()

	config := extractEnvVariables(t)

	return &IntegrationTestSetup{
		Config: config,
		Client: createAuthorizedHTTPClient(config.APIToken),
	}
}

func extractEnvVariables(t *testing.T) TestConfig {
	t.Helper()

	orgIDStr := getRequiredEnvVar(t, "SNYK_ORG_ID")
	orgID, err := uuid.Parse(orgIDStr)
	if err != nil {
		t.Fatalf("Invalid SNYK_ORG_ID format: %v", err)
	}

	baseURL := getRequiredEnvVar(t, "SNYK_API_BASE_URL")
	if _, err := url.Parse(baseURL); err != nil {
		t.Fatalf("Invalid base URL: %v", err)
	}

	snykAPIToken := getRequiredEnvVar(t, "SNYK_API_TOKEN")

	return TestConfig{
		BaseURL:  baseURL,
		OrgID:    orgID,
		APIToken: snykAPIToken,
	}
}

func getRequiredEnvVar(t *testing.T, name string) string {
	t.Helper()
	value, exists := os.LookupEnv(name)
	if !exists {
		t.Fatalf("Required environment variable %s is not set", name)
	}
	if value == "" {
		t.Fatalf("Required environment variable %s is empty", name)
	}
	return value
}

type authRoundTripper struct {
	token string
}

func (art *authRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	r.Header.Set("Authorization", fmt.Sprintf("token %s", art.token))
	return http.DefaultTransport.RoundTrip(r) //nolint:wrapcheck // Not an issue for this test util.
}

func createAuthorizedHTTPClient(token string) *http.Client {
	return &http.Client{
		Transport: &authRoundTripper{
			token: token,
		},
	}
}
