package lowlevel_fileupload_test

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	lowlevel_fileupload "github.com/snyk/cli-extension-os-flows/internal/fileupload/lowlevel"
)

func TestClient_CreateRevision(t *testing.T) {
	orgID := uuid.MustParse("9102b78b-c28d-4392-a39f-08dd26fd9622")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/vnd.api+json", r.Header.Get("Content-Type"))
		assert.Equal(t, "gzip", r.Header.Get("Content-Encoding"))
		assert.Equal(t, fmt.Sprintf("/hidden/orgs/%s/upload_revisions", orgID), r.URL.Path)
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

	resp, err := c.CreateRevision(context.Background(), orgID)

	require.NoError(t, err)
	expectedID := uuid.MustParse("a7d975fb-2076-49b7-bc1f-31c395c3ce93")
	assert.Equal(t, expectedID, resp.Data.ID)
}

func TestClient_CreateRevision_EmptyOrgID(t *testing.T) {
	c := lowlevel_fileupload.NewClient(lowlevel_fileupload.Config{
		BaseURL: "http://example.com",
	})

	resp, err := c.CreateRevision(context.Background(), uuid.Nil)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, lowlevel_fileupload.ErrEmptyOrgID)
}

func TestClient_CreateRevision_ServerError(t *testing.T) {
	orgID := uuid.MustParse("9102b78b-c28d-4392-a39f-08dd26fd9622")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	c := lowlevel_fileupload.NewClient(lowlevel_fileupload.Config{
		BaseURL: srv.URL,
	})

	resp, err := c.CreateRevision(context.Background(), orgID)

	assert.Nil(t, resp)
	var httpErr *lowlevel_fileupload.HTTPError
	assert.ErrorAs(t, err, &httpErr)
	assert.Equal(t, http.StatusInternalServerError, httpErr.StatusCode)
	assert.Equal(t, "create upload revision", httpErr.Operation)
}

func TestClient_UploadFiles(t *testing.T) {
	orgID := uuid.MustParse("9102b78b-c28d-4392-a39f-08dd26fd9622")
	revID := uuid.MustParse("ff1bd2c6-7a5f-48fb-9a5b-52d711c8b47f")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Contains(t, r.Header.Get("Content-Type"), "multipart/form-data")
		assert.Equal(t, "gzip", r.Header.Get("Content-Encoding"))
		assert.Equal(t, fmt.Sprintf("/hidden/orgs/%s/upload_revisions/%s/files", orgID, revID), r.URL.Path)
		assert.Equal(t, "2024-10-15", r.URL.Query().Get("version"))

		// Parse multipart form data
		contentType := r.Header.Get("Content-Type")
		_, params, err := mime.ParseMediaType(contentType)
		require.NoError(t, err)
		boundary := params["boundary"]
		require.NotEmpty(t, boundary, "multipart boundary should be present")

		gzipReader, err := gzip.NewReader(r.Body)
		require.NoError(t, err)
		reader := multipart.NewReader(gzipReader, boundary)

		// Read the first (and should be only) part
		part, err := reader.NextPart()
		require.NoError(t, err)

		// Validate form field name and filename
		assert.Equal(t, "foo/bar", part.FormName())
		assert.Equal(t, "bar", part.FileName()) // filename is just the base name

		// Read and validate file content
		content, err := io.ReadAll(part)
		require.NoError(t, err)
		assert.Equal(t, "asdf", string(content))

		// Ensure no more parts
		_, err = reader.NextPart()
		assert.Equal(t, io.EOF, err)

		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := lowlevel_fileupload.NewClient(lowlevel_fileupload.Config{
		BaseURL: srv.URL,
	})

	mockFS := fstest.MapFS{
		"foo/bar": {Data: []byte("asdf")},
	}
	fd, err := mockFS.Open("foo/bar")
	require.NoError(t, err)

	err = c.UploadFiles(context.Background(),
		orgID,
		revID,
		[]lowlevel_fileupload.UploadFile{
			{Path: "foo/bar", File: fd},
		})

	require.NoError(t, err)
}

func TestClient_UploadFiles_MultipleFiles(t *testing.T) {
	orgID := uuid.MustParse("9102b78b-c28d-4392-a39f-08dd26fd9622")
	revID := uuid.MustParse("ff1bd2c6-7a5f-48fb-9a5b-52d711c8b47f")
	expectedFiles := map[string]string{
		"file1.txt":  "content1",
		"file2.json": "content2",
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Contains(t, r.Header.Get("Content-Type"), "multipart/form-data")
		assert.Equal(t, "gzip", r.Header.Get("Content-Encoding"))
		assert.Equal(t, fmt.Sprintf("/hidden/orgs/%s/upload_revisions/%s/files", orgID, revID), r.URL.Path)
		assert.Equal(t, "2024-10-15", r.URL.Query().Get("version"))

		// Parse multipart form data
		contentType := r.Header.Get("Content-Type")
		_, params, err := mime.ParseMediaType(contentType)
		require.NoError(t, err)
		boundary := params["boundary"]
		require.NotEmpty(t, boundary, "multipart boundary should be present")

		gzipReader, err := gzip.NewReader(r.Body)
		require.NoError(t, err)
		reader := multipart.NewReader(gzipReader, boundary)
		filesReceived := make(map[string]string)

		// Read all parts
		for {
			part, err := reader.NextPart()
			if errors.Is(err, io.EOF) {
				break
			}
			require.NoError(t, err)

			// Read content
			content, err := io.ReadAll(part)
			require.NoError(t, err)

			// Store for validation (use form name which is the full path)
			filesReceived[part.FormName()] = string(content)
		}

		// Validate all expected files were received
		assert.Equal(t, expectedFiles, filesReceived)

		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := lowlevel_fileupload.NewClient(lowlevel_fileupload.Config{
		BaseURL: srv.URL,
	})

	mockFS := fstest.MapFS{
		"file1.txt":  {Data: []byte("content1")},
		"file2.json": {Data: []byte("content2")},
	}

	file1, err := mockFS.Open("file1.txt")
	require.NoError(t, err)
	file2, err := mockFS.Open("file2.json")
	require.NoError(t, err)

	err = c.UploadFiles(context.Background(),
		orgID,
		revID,
		[]lowlevel_fileupload.UploadFile{
			{Path: "file1.txt", File: file1},
			{Path: "file2.json", File: file2},
		})

	require.NoError(t, err)
}

func TestClient_UploadFiles_EmptyOrgID(t *testing.T) {
	revID := uuid.MustParse("ff1bd2c6-7a5f-48fb-9a5b-52d711c8b47f")

	c := lowlevel_fileupload.NewClient(lowlevel_fileupload.Config{
		BaseURL: "http://example.com",
	})

	mockFS := fstest.MapFS{
		"test.txt": {Data: []byte("content")},
	}
	file, err := mockFS.Open("test.txt")
	require.NoError(t, err)

	err = c.UploadFiles(context.Background(),
		uuid.Nil, // empty orgID
		revID,
		[]lowlevel_fileupload.UploadFile{
			{Path: "test.txt", File: file},
		})

	assert.Error(t, err)
	assert.ErrorIs(t, err, lowlevel_fileupload.ErrEmptyOrgID)
}

func TestClient_UploadFiles_EmptyRevisionID(t *testing.T) {
	orgID := uuid.MustParse("9102b78b-c28d-4392-a39f-08dd26fd9622")

	c := lowlevel_fileupload.NewClient(lowlevel_fileupload.Config{
		BaseURL: "http://example.com",
	})

	mockFS := fstest.MapFS{
		"test.txt": {Data: []byte("content")},
	}
	file, err := mockFS.Open("test.txt")
	require.NoError(t, err)

	err = c.UploadFiles(context.Background(),
		orgID,
		uuid.Nil, // empty revisionID
		[]lowlevel_fileupload.UploadFile{
			{Path: "test.txt", File: file},
		})

	assert.Error(t, err)
	assert.ErrorIs(t, err, lowlevel_fileupload.ErrEmptyRevisionID)
}

func TestClient_UploadFiles_FileSizeLimit(t *testing.T) {
	orgID := uuid.MustParse("9102b78b-c28d-4392-a39f-08dd26fd9622")
	revID := uuid.MustParse("ff1bd2c6-7a5f-48fb-9a5b-52d711c8b47f")

	c := lowlevel_fileupload.NewClient(lowlevel_fileupload.Config{
		BaseURL: "http://example.com",
	})

	largeContent := make([]byte, lowlevel_fileupload.FileSizeLimit+1)
	mockFS := fstest.MapFS{
		"large_file.txt": {Data: largeContent},
	}

	file, err := mockFS.Open("large_file.txt")
	require.NoError(t, err)

	err = c.UploadFiles(context.Background(),
		orgID,
		revID,
		[]lowlevel_fileupload.UploadFile{
			{Path: "large_file.txt", File: file},
		})

	assert.Error(t, err)
	var fileSizeErr *lowlevel_fileupload.FileSizeLimitError
	assert.ErrorAs(t, err, &fileSizeErr)
	assert.Equal(t, "large_file.txt", fileSizeErr.FilePath)
	assert.Equal(t, int64(lowlevel_fileupload.FileSizeLimit+1), fileSizeErr.FileSize)
	assert.Equal(t, int64(lowlevel_fileupload.FileSizeLimit), fileSizeErr.Limit)
}

func TestClient_UploadFiles_FileCountLimit(t *testing.T) {
	orgID := uuid.MustParse("9102b78b-c28d-4392-a39f-08dd26fd9622")
	revID := uuid.MustParse("ff1bd2c6-7a5f-48fb-9a5b-52d711c8b47f")

	c := lowlevel_fileupload.NewClient(lowlevel_fileupload.Config{
		BaseURL: "http://example.com",
	})

	files := make([]lowlevel_fileupload.UploadFile, lowlevel_fileupload.FileCountLimit+1)
	mockFS := fstest.MapFS{}

	for i := range lowlevel_fileupload.FileCountLimit + 1 {
		filename := fmt.Sprintf("file%d.txt", i)
		mockFS[filename] = &fstest.MapFile{Data: []byte("content")}

		file, err := mockFS.Open(filename)
		require.NoError(t, err)

		files[i] = lowlevel_fileupload.UploadFile{
			Path: filename,
			File: file,
		}
	}

	err := c.UploadFiles(context.Background(), orgID, revID, files)

	assert.Error(t, err)
	var fileCountErr *lowlevel_fileupload.FileCountLimitError
	assert.ErrorAs(t, err, &fileCountErr)
	assert.Equal(t, lowlevel_fileupload.FileCountLimit+1, fileCountErr.Count)
	assert.Equal(t, lowlevel_fileupload.FileCountLimit, fileCountErr.Limit)
}

func TestClient_UploadFiles_DirectoryError(t *testing.T) {
	orgID := uuid.MustParse("9102b78b-c28d-4392-a39f-08dd26fd9622")
	revID := uuid.MustParse("ff1bd2c6-7a5f-48fb-9a5b-52d711c8b47f")

	c := lowlevel_fileupload.NewClient(lowlevel_fileupload.Config{
		BaseURL: "http://example.com",
	})

	mockFS := fstest.MapFS{
		"test-directory": &fstest.MapFile{
			Mode: fs.ModeDir,
		},
	}

	dirFile, err := mockFS.Open("test-directory")
	require.NoError(t, err)

	err = c.UploadFiles(context.Background(),
		orgID,
		revID,
		[]lowlevel_fileupload.UploadFile{
			{Path: "test-directory", File: dirFile},
		})

	assert.Error(t, err)
	var dirErr *lowlevel_fileupload.DirectoryError
	assert.ErrorAs(t, err, &dirErr)
	assert.Equal(t, "test-directory", dirErr.Path)
}

func TestClient_UploadFiles_EmptyFileList(t *testing.T) {
	orgID := uuid.MustParse("9102b78b-c28d-4392-a39f-08dd26fd9622")
	revID := uuid.MustParse("ff1bd2c6-7a5f-48fb-9a5b-52d711c8b47f")

	c := lowlevel_fileupload.NewClient(lowlevel_fileupload.Config{
		BaseURL: "http://example.com",
	})

	err := c.UploadFiles(context.Background(), orgID, revID, []lowlevel_fileupload.UploadFile{})

	assert.Error(t, err)
	assert.ErrorIs(t, err, lowlevel_fileupload.ErrNoFilesProvided)
}

func TestClient_SealRevision(t *testing.T) {
	orgID := uuid.MustParse("9102b78b-c28d-4392-a39f-08dd26fd9622")
	revID := uuid.MustParse("ff1bd2c6-7a5f-48fb-9a5b-52d711c8b47f")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPatch, r.Method)
		assert.Equal(t, "application/vnd.api+json", r.Header.Get("Content-Type"))
		assert.Equal(t, "gzip", r.Header.Get("Content-Encoding"))
		assert.Equal(t, fmt.Sprintf("/hidden/orgs/%s/upload_revisions/%s", orgID, revID), r.URL.Path)
		assert.Equal(t, "2024-10-15", r.URL.Query().Get("version"))

		w.WriteHeader(http.StatusOK)
		//nolint:errcheck // Not needed in test.
		w.Write([]byte(`{
			"data": {
				"attributes": {
					"revision_type": "snapshot",
					"sealed": true
				},
				"id": "ff1bd2c6-7a5f-48fb-9a5b-52d711c8b47f",
				"type": "upload_revision"
			}
		}`))
	}))
	c := lowlevel_fileupload.NewClient(lowlevel_fileupload.Config{
		BaseURL: srv.URL,
	})

	resp, err := c.SealRevision(context.Background(), orgID, revID)

	require.NoError(t, err)
	assert.Equal(t, revID, resp.Data.ID)
	assert.True(t, resp.Data.Attributes.Sealed)
}

func TestClient_SealRevision_EmptyOrgID(t *testing.T) {
	revID := uuid.MustParse("ff1bd2c6-7a5f-48fb-9a5b-52d711c8b47f")

	c := lowlevel_fileupload.NewClient(lowlevel_fileupload.Config{
		BaseURL: "http://example.com",
	})

	resp, err := c.SealRevision(context.Background(),
		uuid.Nil, // empty orgID
		revID,
	)

	assert.Error(t, err)
	assert.ErrorIs(t, err, lowlevel_fileupload.ErrEmptyOrgID)
	assert.Nil(t, resp)
}

func TestClient_SealRevision_EmptyRevisionID(t *testing.T) {
	orgID := uuid.MustParse("9102b78b-c28d-4392-a39f-08dd26fd9622")

	c := lowlevel_fileupload.NewClient(lowlevel_fileupload.Config{
		BaseURL: "http://example.com",
	})

	resp, err := c.SealRevision(context.Background(),
		orgID,
		uuid.Nil, // empty revisionID
	)

	assert.Error(t, err)
	assert.ErrorIs(t, err, lowlevel_fileupload.ErrEmptyRevisionID)
	assert.Nil(t, resp)
}
