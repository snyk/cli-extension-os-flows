package lowlevel_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/fileupload/lowlevel"
)

type CustomRoundTripper struct{}

func (crt *CustomRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	r.Header.Set("foo", "bar")
	return http.DefaultTransport.RoundTrip(r)
}

func Test_WithHTTPClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fooValue := r.Header.Get("foo")
		assert.Equal(t, "bar", fooValue)

		resp, err := json.Marshal(lowlevel.UploadRevisionResponseBody{})
		require.NoError(t, err)

		w.WriteHeader(http.StatusCreated)
		//nolint:errcheck // Not needed in test.
		w.Write(resp)
	}))
	defer srv.Close()
	customClient := srv.Client()
	customClient.Transport = &CustomRoundTripper{}

	llc := lowlevel.NewClient(lowlevel.Config{
		BaseURL: srv.URL,
	}, lowlevel.WithHTTPClient(customClient))

	_, err := llc.CreateRevision(context.Background(), uuid.New())

	require.NoError(t, err)
}
