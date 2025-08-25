package reachability

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
)

// Config contains configuration options for the SCA Engine client.
type Config struct {
	BaseURL      string
	PollInterval time.Duration
	PollTimeout  time.Duration
}

// SCAEngineClient provides functionality for interacting with the SCA Engine reachability API.
type SCAEngineClient struct {
	httpClient *http.Client
	cfg        Config
}

const (
	apiVersion = "2024-10-15"

	minPollInteval      = 1 * time.Second
	defaultPollInterval = 2 * time.Second
	defaultPollTimeout  = 2 * time.Minute
)

// Client defines the interface for reachability analysis operations.
type Client interface {
	StartReachabilityAnalysis(ctx context.Context, orgID OrgID, bundleID BundleHash) (ID, error)
	WaitForReachabilityAnalysis(ctx context.Context, orgID OrgID, reachabilityID ID) error
}

var _ Client = (*SCAEngineClient)(nil)

// NewClient creates a new SCA Engine client with the provided HTTP client and configuration.
// It applies default values for PollInterval and PollTimeout if not specified, and enforces minimum bounds.
func NewClient(httpClient *http.Client, cfg Config) *SCAEngineClient {
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = defaultPollInterval
	}

	if cfg.PollTimeout <= 0 {
		cfg.PollTimeout = defaultPollTimeout
	}

	cfg.PollInterval = max(minPollInteval, cfg.PollInterval)

	return &SCAEngineClient{httpClient, cfg}
}

// StartReachabilityAnalysis initiates a reachability analysis for the given bundle and returns the analysis ID.
func (sec *SCAEngineClient) StartReachabilityAnalysis(ctx context.Context, orgID OrgID, bundleID BundleHash) (ID, error) {
	if orgID == uuid.Nil {
		return uuid.Nil, ErrEmptyOrgID
	}

	body := StartReachabilityRequestBody{
		Data: StartReachabilityRequestData{
			Type: ResourceTypeReachability,
			Attributes: StartReachabilityAttributes{
				BundleID: bundleID,
			},
		},
	}

	buff := bytes.NewBuffer(nil)
	if err := json.NewEncoder(buff).Encode(body); err != nil {
		return uuid.Nil, fmt.Errorf("failed to encode reachability request body: %w", err)
	}

	url := fmt.Sprintf("%s/hidden/orgs/%s/reachability?version=%s", sec.cfg.BaseURL, orgID, apiVersion)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, buff)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to create reachability request: %w", err)
	}
	req.Header.Set("Content-Type", "application/vnd.api+json")

	res, err := sec.httpClient.Do(req)
	if err != nil {
		return uuid.Nil, fmt.Errorf("error making reachability request: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusCreated {
		return uuid.Nil, handleUnexpectedStatusCodes(res.Body, res.StatusCode, res.Status, "reachability analysis")
	}

	var respBody StartReachabilityResponseBody
	if err := json.NewDecoder(res.Body).Decode(&respBody); err != nil {
		return uuid.Nil, fmt.Errorf("failed to decode reachability response body: %w", err)
	}

	return respBody.Data.ID, nil
}

// WaitForReachabilityAnalysis polls for the completion of a reachability analysis until it finishes, fails, or times out.
// It returns nil when the analysis completes successfully, or an appropriate error for other outcomes.
func (sec *SCAEngineClient) WaitForReachabilityAnalysis(ctx context.Context, orgID OrgID, reachabilityID ID) error {
	timeout := time.After(sec.cfg.PollTimeout)
	t := time.NewTicker(sec.cfg.PollInterval)
	defer t.Stop()

	for {
		status, err := sec.getReachabilityAnalysisStatus(ctx, orgID, reachabilityID)
		if err != nil {
			return err
		}
		switch status {
		case ScanStatusDone:
			return nil
		case ScanStatusFailed:
			return ErrScanFailed
		case ScanStatusTimeout:
			return ErrScanTimedOut
		case ScanStatusUnknown:
			return ErrScanStatusUnknown
		case ScanStatusInProgress:
			// Continue polling for status
		default:
			return NewUnexpectedScanStatusError(status)
		}

		select {
		case <-ctx.Done():
			return ErrPollCancelled
		case <-timeout:
			return ErrPollTimedOut
		case <-t.C:
			continue
		}
	}
}

func (sec *SCAEngineClient) getReachabilityAnalysisStatus(ctx context.Context, orgID OrgID, reachabilityID ID) (ScanStatus, error) {
	if orgID == uuid.Nil {
		return "", ErrEmptyOrgID
	}

	if reachabilityID == uuid.Nil {
		return "", ErrEmptyReachabilityID
	}

	url := fmt.Sprintf("%s/hidden/orgs/%s/scans/%s/reachability?version=%s", sec.cfg.BaseURL, orgID, reachabilityID, apiVersion)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return "", fmt.Errorf("failed to create reachability request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.api+json")

	res, err := sec.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("error making reachability request: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return "", handleUnexpectedStatusCodes(res.Body, res.StatusCode, res.Status, "reachability analysis")
	}

	var respBody GetReachabilityResponseBody
	if err := json.NewDecoder(res.Body).Decode(&respBody); err != nil {
		return "", fmt.Errorf("failed to decode reachability response body: %w", err)
	}

	return respBody.Data.Attributes.Status, nil
}

// handleUnexpectedStatusCodes processes non-success HTTP responses and returns appropriate errors.
// It attempts to parse Snyk API error responses when possible, falling back to generic HTTP errors.
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
