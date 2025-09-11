package settings_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/settings"
)

func Test_IsReachabilityEnabled(t *testing.T) {
	orgID := uuid.New()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, fmt.Sprintf("/rest/orgs/%s/settings/opensource", orgID), r.URL.Path)

		w.Write([]byte(
			`{
			"jsonapi": {
				"version": "1.0"
			},
			"data": {
				"type": "opensource_settings",
				"attributes": {
					"reachability": {
						"enabled": true
					}
				}
			}
		}`))
	}))
	defer srv.Close()
	rsc := settings.NewClient(srv.Client(), settings.Config{BaseURL: srv.URL})

	isEnabled, err := rsc.IsReachabilityEnabled(t.Context(), orgID)
	require.NoError(t, err)

	assert.Equal(t, true, isEnabled)
}

func Test_IsReachabilityEnabled_ServerError(t *testing.T) {
	orgID := uuid.New()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, fmt.Sprintf("/rest/orgs/%s/settings/opensource", orgID), r.URL.Path)

		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	rsc := settings.NewClient(srv.Client(), settings.Config{BaseURL: srv.URL})

	_, err := rsc.IsReachabilityEnabled(t.Context(), orgID)

	assert.ErrorContains(t, err, "unsuccessful request to reachability settings")
}
