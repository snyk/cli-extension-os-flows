package deeproxy

import "net/http"

// Opt is a function that configures an deeproxyClient instance.
type Opt func(*HTTPClient)

// WithHTTPClient sets a custom HTTP client for the filters client.
func WithHTTPClient(httpClient *http.Client) Opt {
	return func(c *HTTPClient) {
		c.httpClient = httpClient
	}
}
