package lowlevel_fileupload_test

import (
	"context"
	"net/http"
	"testing"

	lowlevel_fileupload "github.com/snyk/cli-extension-os-flows/internal/fileupload/lowlevel"
	"github.com/stretchr/testify/require"
)

type RountTripperCustom struct{}

func (rtc RountTripperCustom) RoundTrip(r *http.Request) (*http.Response, error) {
	return http.DefaultTransport.RoundTrip(r)
}

func Test_LowLevelClient(t *testing.T) {
	ctx := context.Background()
	orgID := "5c36bcc5-2a0c-4ac7-8611-d9ba3c368132"
	customhttp := *http.DefaultClient
	customhttp.Transport = RountTripperCustom{}
	llc := lowlevel_fileupload.NewClient(lowlevel_fileupload.Config{
		BaseURL: "https://api.dev.snyk.io/",
	}, lowlevel_fileupload.WithHTTPClient(&customhttp))

	id, err := llc.CreateRevision(ctx, orgID)
	require.NoError(t, err)

	err = llc.UploadFiles(ctx, orgID, id, []lowlevel_fileupload.UploadFile{lowlevel_fileupload.UploadFile{FilePath: "./client.go", Name: "client.go"}})
	require.NoError(t, err)

	t.Log(id)
}
