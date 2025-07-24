package lowlevel_fileupload

import "net/http"

type Opt func(*Client)

func WithHTTPClient(httpClient *http.Client) Opt {
	return func(c *Client) {
		c.httpClient = httpClient
	}
}
