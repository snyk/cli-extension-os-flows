package settings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/google/uuid"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
)

// Config contains configuration for the reachability settings client.
type Config struct {
	BaseURL string
}

// HTTPClient provides functionality for interacting with the settings API.
type HTTPClient struct {
	httpClient *http.Client
	cfg        Config
}

// Client defines the interface for accessing reachability settings.
type Client interface {
	IsReachabilityEnabled(ctx context.Context, orgID OrgID) (bool, error)
}

var _ Client = (*HTTPClient)(nil)

const apiVersion = "2024-10-15"

// NewClient creates a new RegistryClient with the provided HTTP client and configuration.
func NewClient(httpClient *http.Client, cfg Config) *HTTPClient {
	return &HTTPClient{httpClient, cfg}
}

// IsReachabilityEnabled checks if reachability analysis is enabled for the given organization.
func (rc *HTTPClient) IsReachabilityEnabled(ctx context.Context, orgID OrgID) (bool, error) {
	if orgID == uuid.Nil {
		return false, ErrEmptyOrgID
	}

	url := fmt.Sprintf("%s/rest/orgs/%s/settings/opensource?version=%s", rc.cfg.BaseURL, orgID, apiVersion)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return false, fmt.Errorf("failed to create reachability settings request: %w", err)
	}

	res, err := rc.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("error making reachability setting request: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return false, handleUnexpectedStatusCodes(res.Body, res.StatusCode, res.Status, "reachability settings")
	}

	var respBody ResponseBody
	if err := json.NewDecoder(res.Body).Decode(&respBody); err != nil {
		return false, fmt.Errorf("failed to decode reachability settings response body: %w", err)
	}

	return respBody.Data.Attributes.Reachability.Enabled, nil
}

func handleUnexpectedStatusCodes(body io.ReadCloser, statusCode int, status, operation string) error {
	bts, err := io.ReadAll(body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if len(bts) > 0 {
		snykErrorList, parseErr := snyk_errors.FromJSONAPIErrorBytes(bts)
		if parseErr == nil && len(snykErrorList) > 0 && snykErrorList[0].Title != "" {
			errsToJoin := []error{}
			for i := range snykErrorList {
				errsToJoin = append(errsToJoin, snykErrorList[i])
			}
			return fmt.Errorf("api error during %s: %w", operation, errors.Join(errsToJoin...))
		}
	}

	return NewHTTPError(statusCode, status, operation, bts)
}
