package reachability_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/reachability"
)

func testOrgID() reachability.OrgID {
	return uuid.New()
}

func testReachabilityID() reachability.ID {
	return uuid.New()
}

// TestServerConfig contains the expected request details and desired response.
type TestServerConfig struct {
	ExpectedMethod     string
	ExpectedAPIVersion string
	ExpectedPath       string
	ResponseStatus     int
	ResponseBodies     []string // Cycles through these responses for polling scenarios
}

func setupTest(t *testing.T, serverConfig *TestServerConfig, clientConfig ...reachability.Config) (rc *reachability.SCAEngineClient, cc *int32) {
	t.Helper()

	var callCount int32
	handler := func(w http.ResponseWriter, r *http.Request) {
		if serverConfig.ExpectedAPIVersion != "" {
			assert.Equal(t, serverConfig.ExpectedAPIVersion, r.URL.Query().Get("version"))
		}
		if serverConfig.ExpectedPath != "" {
			assert.Equal(t, serverConfig.ExpectedPath, r.URL.Path)
		}
		if serverConfig.ExpectedMethod != "" {
			assert.Equal(t, serverConfig.ExpectedMethod, r.Method)
		}

		w.WriteHeader(serverConfig.ResponseStatus)

		// Handle multiple response bodies for polling scenarios
		if len(serverConfig.ResponseBodies) > 0 {
			count := atomic.AddInt32(&callCount, 1)
			index := int(count - 1)
			if index >= len(serverConfig.ResponseBodies) {
				index = len(serverConfig.ResponseBodies) - 1 // Use last response for subsequent calls
			}
			w.Write([]byte(serverConfig.ResponseBodies[index]))
		}
	}

	srv := httptest.NewServer(http.HandlerFunc(handler))
	t.Cleanup(func() {
		srv.Close()
	})

	cfg := reachability.Config{BaseURL: srv.URL}
	if len(clientConfig) > 0 {
		// Override with provided config but preserve BaseURL
		cfg = clientConfig[0]
		cfg.BaseURL = srv.URL
	}

	client := reachability.NewClient(srv.Client(), cfg)
	return client, &callCount
}

func singleResponse(body string) []string {
	return []string{body}
}

func pollingResponses(statuses ...reachability.ScanStatus) []string {
	responses := make([]string, len(statuses))
	for i, status := range statuses {
		responses[i] = reachabilityStatusBody(status)
	}
	return responses
}

func reachabilityStatusBody(status reachability.ScanStatus) string {
	return fmt.Sprintf(
		`{
			"data": {
				"attributes": {
					"status": "%s"
				}
			}
		}`,
		status,
	)
}

func Test_StartReachabilityAnalysis(t *testing.T) {
	orgID := testOrgID()
	expectedReachabilityID := testReachabilityID()

	rc, _ := setupTest(t, &TestServerConfig{
		ExpectedMethod:     http.MethodPost,
		ExpectedAPIVersion: "2024-10-15",
		ExpectedPath:       fmt.Sprintf("/hidden/orgs/%s/reachability", orgID),
		ResponseStatus:     http.StatusCreated,
		ResponseBodies: singleResponse(fmt.Sprintf(`{
			"data": {
				"id": "%s"
			}
		}`, expectedReachabilityID)),
	})

	reachabilityID, err := rc.StartReachabilityAnalysis(t.Context(), orgID, "bundle-hash")
	require.NoError(t, err)

	assert.Equal(t, expectedReachabilityID, reachabilityID)
}

func Test_StartReachabilityAnalysis_ServerError(t *testing.T) {
	orgID := testOrgID()

	rc, _ := setupTest(t, &TestServerConfig{
		ResponseStatus: http.StatusInternalServerError,
		ResponseBodies: singleResponse(`{"errors": [{"title": "Internal server error"}]}`),
	})

	_, err := rc.StartReachabilityAnalysis(t.Context(), orgID, "bundle-hash")

	assert.ErrorContains(t, err, "api error during reachability analysis: Internal server error")
}

func Test_WaitForReachabilityAnalysis_ImmediateSuccess(t *testing.T) {
	orgID := testOrgID()
	reachabilityID := testReachabilityID()

	rc, _ := setupTest(t, &TestServerConfig{
		ExpectedMethod:     http.MethodGet,
		ExpectedAPIVersion: "2024-10-15",
		ExpectedPath:       fmt.Sprintf("/hidden/orgs/%s/scans/%s/reachability", orgID, reachabilityID),
		ResponseStatus:     http.StatusOK,
		ResponseBodies:     singleResponse(reachabilityStatusBody(reachability.ScanStatusDone)),
	})

	err := rc.WaitForReachabilityAnalysis(context.Background(), orgID, reachabilityID)
	require.NoError(t, err)
}

func Test_WaitForReachabilityAnalysis_PollingSuccess(t *testing.T) {
	orgID := testOrgID()
	reachabilityID := testReachabilityID()

	rc, cc := setupTest(t, &TestServerConfig{
		ResponseStatus: http.StatusOK,
		ResponseBodies: pollingResponses(
			reachability.ScanStatusInProgress,
			reachability.ScanStatusDone,
		),
	}, reachability.Config{
		PollInterval: 1 * time.Second,
	})

	err := rc.WaitForReachabilityAnalysis(context.Background(), orgID, reachabilityID)
	require.NoError(t, err)

	assert.Equal(t, int32(2), *cc)
}

func Test_WaitForReachabilityAnalysis_ScanFailed(t *testing.T) {
	orgID := testOrgID()
	reachabilityID := testReachabilityID()

	rc, _ := setupTest(t, &TestServerConfig{
		ResponseStatus: http.StatusOK,
		ResponseBodies: singleResponse(reachabilityStatusBody(reachability.ScanStatusFailed)),
	})

	err := rc.WaitForReachabilityAnalysis(context.Background(), orgID, reachabilityID)
	assert.ErrorIs(t, err, reachability.ErrScanFailed)
}

func Test_WaitForReachabilityAnalysis_ScanTimeout(t *testing.T) {
	orgID := testOrgID()
	reachabilityID := testReachabilityID()

	rc, _ := setupTest(t, &TestServerConfig{
		ResponseStatus: http.StatusOK,
		ResponseBodies: singleResponse(reachabilityStatusBody(reachability.ScanStatusTimeout)),
	})

	err := rc.WaitForReachabilityAnalysis(context.Background(), orgID, reachabilityID)
	assert.ErrorIs(t, err, reachability.ErrScanTimedOut)
}

func Test_WaitForReachabilityAnalysis_PollTimeout(t *testing.T) {
	orgID := testOrgID()
	reachabilityID := testReachabilityID()

	rc, _ := setupTest(t, &TestServerConfig{
		ResponseStatus: http.StatusOK,
		ResponseBodies: singleResponse(reachabilityStatusBody(reachability.ScanStatusInProgress)),
	}, reachability.Config{
		PollInterval: 1 * time.Second,
		PollTimeout:  200 * time.Millisecond,
	})

	err := rc.WaitForReachabilityAnalysis(context.Background(), orgID, reachabilityID)

	assert.ErrorIs(t, err, reachability.ErrPollTimedOut)
}

func Test_WaitForReachabilityAnalysis_ContextCancelled(t *testing.T) {
	orgID := testOrgID()
	reachabilityID := testReachabilityID()

	rc, _ := setupTest(t, &TestServerConfig{
		ResponseStatus: http.StatusOK,
		ResponseBodies: singleResponse(reachabilityStatusBody(reachability.ScanStatusInProgress)),
	}, reachability.Config{
		PollInterval: 1 * time.Second,
		PollTimeout:  5 * time.Second,
	})

	ctx, cancel := context.WithCancel(context.Background())

	// Cancel context after a short delay
	go func() {
		time.Sleep(150 * time.Millisecond)
		cancel()
	}()

	err := rc.WaitForReachabilityAnalysis(ctx, orgID, reachabilityID)

	assert.ErrorIs(t, err, reachability.ErrPollCancelled)
}

func Test_WaitForReachabilityAnalysis_InternalServerError(t *testing.T) {
	orgID := testOrgID()
	reachabilityID := testReachabilityID()

	rc, _ := setupTest(t, &TestServerConfig{
		ResponseStatus: http.StatusInternalServerError,
		ResponseBodies: singleResponse(`{"errors": [{"title": "Internal server error"}]}`),
	})

	err := rc.WaitForReachabilityAnalysis(context.Background(), orgID, reachabilityID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "api error during reachability analysis")
}
