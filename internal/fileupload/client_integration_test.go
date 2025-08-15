package fileupload_test

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/cli-extension-os-flows/internal/fileupload"
	"github.com/snyk/cli-extension-os-flows/internal/fileupload/uploadrevision"
)

func TestUploadFileIntegration(t *testing.T) {
	fileUploadClient := setupFileUploadClient(t)

	files := []uploadrevision.LoadedFile{
		{Path: "src/main.go", Content: "package main"},
	}

	dir, dirCleanup := createDirWithFiles(t, files)
	defer dirCleanup()

	fileuploadRevisionID, err := fileUploadClient.CreateRevisionFromFile(t.Context(), filepath.Join(dir.Name(), files[0].Path), fileupload.UploadOptions{})
	if err != nil {
		t.Errorf("failed to create fileupload revision: %s", err.Error())
	}
	assert.NotEqual(t, uuid.Nil, fileuploadRevisionID)
}

func TestUploadDirectoryIntegration(t *testing.T) {
	fileUploadClient := setupFileUploadClient(t)

	files := []uploadrevision.LoadedFile{
		{Path: "src/main.go", Content: "package main"},
		{Path: "src/utils.go", Content: "package utils"},
		{Path: "README.md", Content: "# Project"},
	}

	dir, dirCleanup := createDirWithFiles(t, files)
	defer dirCleanup()

	fileuploadRevisionID, err := fileUploadClient.CreateRevisionFromDir(t.Context(), dir.Name(), fileupload.UploadOptions{})
	if err != nil {
		t.Errorf("failed to create fileupload revision: %s", err.Error())
	}
	assert.NotEqual(t, uuid.Nil, fileuploadRevisionID)
}

func TestUploadLargeFileIntegration(t *testing.T) {
	fileUploadClient := setupFileUploadClient(t)

	content := generateFileOfSizeMegabytes(t, 30)
	files := []uploadrevision.LoadedFile{
		{Path: "src/main.go", Content: content},
	}

	dir, dirCleanup := createDirWithFiles(t, files)
	defer dirCleanup()

	fileuploadRevisionID, err := fileUploadClient.CreateRevisionFromFile(t.Context(), filepath.Join(dir.Name(), files[0].Path), fileupload.UploadOptions{})
	if err != nil {
		t.Errorf("failed to create fileupload revision: %s", err.Error())
	}
	assert.NotEqual(t, uuid.Nil, fileuploadRevisionID)
}

func setupFileUploadClient(t *testing.T) fileupload.Client {
	t.Helper()

	if os.Getenv("INTEGRATION") == "" {
		t.Skip("skipping integration test; set INTEGRATION=1 to run")
	}

	envvars := extractEnvVariables(t)
	httpclient := &http.Client{
		Transport: &CustomRoundTripper{
			token: envvars.APIToken,
		},
	}

	return fileupload.NewClient(
		httpclient,
		fileupload.Config{
			BaseURL: envvars.BaseURL,
			OrgID:   envvars.OrgID,
		},
	)
}

func generateFileOfSizeMegabytes(t *testing.T, megabytes int) string {
	t.Helper()
	content := make([]byte, megabytes*1024*1024)
	return string(content)
}

type testConfig struct {
	BaseURL  string
	OrgID    uuid.UUID
	APIToken string
}

func readEnvVar(t *testing.T, name string) string {
	t.Helper()
	value, exists := os.LookupEnv(name)
	if !exists {
		t.Errorf("%v is not set", name)
		t.Fail()
	}
	return value
}

func extractEnvVariables(t *testing.T) testConfig {
	t.Helper()

	baseURL := readEnvVar(t, "SNYK_API_BASE_URL")
	snykAPIToken := readEnvVar(t, "SNYK_API_TOKEN")
	orgID := readEnvVar(t, "SNYK_ORG_ID")

	return testConfig{
		BaseURL:  baseURL,
		OrgID:    uuid.MustParse(orgID),
		APIToken: snykAPIToken,
	}
}

type CustomRoundTripper struct {
	token string
}

func (crt *CustomRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	r.Header.Set("Authorization", fmt.Sprintf("token %s", crt.token))
	return http.DefaultTransport.RoundTrip(r)
}
