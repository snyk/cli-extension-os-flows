package lowlevel_fileupload //nolint:revive // underscore naming is intentional for this internal package

import "net/http"

// Opt is a function that configures an HTTPClient instance.
type Opt func(*HTTPClient)

// WithHTTPClient sets a custom HTTP client for the file upload client.
func WithHTTPClient(httpClient *http.Client) Opt {
	return func(c *HTTPClient) {
		c.httpClient = httpClient
	}
}
