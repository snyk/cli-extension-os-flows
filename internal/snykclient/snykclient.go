// Package snykclient provides a client for interacting with the Snyk API.
package snykclient

import (
	"net/http"
	"time"
)

// Client is used for interacting with the Snyk API.
type Client struct {
	client     *http.Client
	apiBaseURL string
	orgID      string
}

// backoffFn defines the signature for backoff functions.
type backoffFn func()

// GetClient returns the HTTP client.
func (s *Client) GetClient() *http.Client {
	return s.client
}

// GetAPIBaseURL returns the API base URL.
func (s *Client) GetAPIBaseURL() string {
	// TODO: remove this when we go GA.
	return s.apiBaseURL + "/closed-beta/"
}

// GetOrgID returns the organization ID.
func (s *Client) GetOrgID() string {
	return s.orgID
}

// DefaultBackoff is the default backoff function.
var DefaultBackoff backoffFn = func() {
	// TODO: fine tune backoff
	time.Sleep(time.Millisecond * 500)
}

// NewSnykClient creates a new SnykClient instance.
func NewSnykClient(c *http.Client, apiBaseURL, orgID string) *Client {
	return &Client{
		client:     createNonRedirectingHTTPClient(c),
		apiBaseURL: apiBaseURL,
		orgID:      orgID,
	}
}

func createNonRedirectingHTTPClient(c *http.Client) *http.Client {
	newClient := http.Client{
		Transport: c.Transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &newClient
}
