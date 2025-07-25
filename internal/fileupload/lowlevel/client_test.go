package lowlevel_fileupload_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	lowlevel_fileupload "github.com/snyk/cli-extension-os-flows/internal/fileupload/lowlevel"
)

func TestClient_CreateRevision(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/vnd.api+json", r.Header.Get("Content-Type"))
		assert.Equal(t, "/hidden/orgs/5c36bcc5-2a0c-4ac7-8611-d9ba3c368132/upload_revisions", r.URL.Path)
		assert.Equal(t, "2024-10-15", r.URL.Query().Get("version"))

		w.WriteHeader(http.StatusCreated)
		//nolint:errcheck // Not needed in test.
		w.Write([]byte(`{
			"data": {
				"attributes": {
					"revision_type": "snapshot",
					"sealed": false
				},
				"id": "a7d975fb-2076-49b7-bc1f-31c395c3ce93",
				"type": "upload_revision"
			}
		}`))
	}))
	c := lowlevel_fileupload.NewClient(lowlevel_fileupload.Config{
		BaseURL: srv.URL,
	})

	revID, err := c.CreateRevision(context.Background(), "5c36bcc5-2a0c-4ac7-8611-d9ba3c368132")

	require.NoError(t, err)
	assert.Equal(t, "a7d975fb-2076-49b7-bc1f-31c395c3ce93", revID)
}

func TestClient_CreateRevision_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	c := lowlevel_fileupload.NewClient(lowlevel_fileupload.Config{
		BaseURL: srv.URL,
	})

	revID, err := c.CreateRevision(context.Background(), "5c36bcc5-2a0c-4ac7-8611-d9ba3c368132")

	require.Zero(t, revID)
	assert.ErrorContains(t, err, "unsuccessful request")
}

func TestClient_UploadFiles(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO: assert request header, method, content-type

		// TODO: use multi-part lib
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		assert.Equal(t, "asdf", string(body))
	}))
	c := lowlevel_fileupload.NewClient(lowlevel_fileupload.Config{
		BaseURL: srv.URL,
	})

	mockFS := fstest.MapFS{
		"foo/bar": {Data: []byte("asdf")},
	}
	fd, err := mockFS.Open("foo/bar")
	require.NoError(t, err)

	err = c.UploadFiles(context.Background(),
		"5c36bcc5-2a0c-4ac7-8611-d9ba3c368132",
		"a7d975fb-2076-49b7-bc1f-31c395c3ce93",
		[]lowlevel_fileupload.UploadFile{
			{Path: "/foo/bar", File: fd},
		})

	require.NoError(t, err)
}
