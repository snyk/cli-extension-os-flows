package ostest_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	bundlemocks "github.com/snyk/code-client-go/bundle/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-os-flows/internal/bundlestore"
	"github.com/snyk/cli-extension-os-flows/internal/commands/ostest"
	"github.com/snyk/cli-extension-os-flows/internal/errors"
	"github.com/snyk/cli-extension-os-flows/internal/flags"
	svcmocks "github.com/snyk/cli-extension-os-flows/internal/mocks"
)

//go:generate go run github.com/golang/mock/mockgen -package=mocks -destination=../../mocks/mock_codescanner.go github.com/snyk/code-client-go CodeScanner
//go:generate go run github.com/golang/mock/mockgen -package=mocks -destination=../../mocks/mock_bundlestore_client.go github.com/snyk/cli-extension-os-flows/internal/bundlestore Client

var logger = zerolog.New(&bytes.Buffer{})

func TestSBOMTestWorkflow_Reachability(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	ctrlDep := gomock.NewController(t)
	defer ctrlDep.Finish()

	mockBundleHash := "mockHash123abc"

	bundleRespJSON, err := json.Marshal(bundlestore.BundleResponse{
		BundleHash:   mockBundleHash,
		MissingFiles: []string{},
	})
	require.NoError(t, err)

	responses := []svcmocks.MockResponse{
		svcmocks.NewMockResponse("application/json", bundleRespJSON, http.StatusOK),
		svcmocks.NewMockResponse("application/json", bundleRespJSON, http.StatusOK),
	}

	var capturedRequests []*http.Request
	mockService := svcmocks.NewMockSBOMServiceMultiResponse(responses, func(r *http.Request) {
		capturedRequests = append(capturedRequests, r)
	})
	defer mockService.Close()

	mockICTX := createMockInvocationCtxWithURL(t, ctrlDep, nil, mockService.URL)

	mockICTX.GetConfiguration().Set(flags.FlagReachability, true)
	mockICTX.GetConfiguration().Set(flags.FlagSBOM, "testdata/bom.json")
	mockICTX.GetConfiguration().Set(ostest.FeatureFlagSBOMTestReachability, true)

	mockBundle := bundlemocks.NewMockBundle(ctrlDep)
	mockBundle.EXPECT().
		GetBundleHash().
		Return(mockBundleHash).
		Times(1)
	mockCodeScanner := svcmocks.NewMockCodeScanner(ctrl)
	mockCodeScanner.EXPECT().
		Upload(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Return(mockBundle, nil).
		Times(1)

	originalCodeScanner := bundlestore.CodeScanner
	bundlestore.CodeScanner = mockCodeScanner
	t.Cleanup(func() { bundlestore.CodeScanner = originalCodeScanner })

	_, err = ostest.OSWorkflow(mockICTX, []workflow.Data{})
	require.NoError(t, err)

	require.Len(t, capturedRequests, 2)

	assert.Equal(t, http.MethodPost, capturedRequests[0].Method)
	assert.Equal(t, "/bundle", capturedRequests[0].URL.Path)

	assert.Equal(t, http.MethodPut, capturedRequests[1].Method)
	assert.Equal(t, "/bundle/"+mockBundleHash, capturedRequests[1].URL.Path)
}

func TestSBOMTestWorkflow_Reachability_DefaultPath(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	ctrlDep := gomock.NewController(t)
	defer ctrlDep.Finish()

	mockICTX := createMockInvocationCtxWithURL(t, ctrlDep, nil, mockServerURL)
	mockICTX.GetConfiguration().Set(flags.FlagReachability, true)
	mockICTX.GetConfiguration().Set(flags.FlagSBOM, "testdata/bom.json")
	mockICTX.GetConfiguration().Set(ostest.FeatureFlagSBOMTestReachability, true)

	sourceCodePath := "."

	mockBundlestoreClient := svcmocks.NewMockClient(ctrl)
	mockBundlestoreClient.
		EXPECT().
		UploadSourceCode(gomock.Any(), sourceCodePath).
		Return("source-code-hash", nil).
		Times(1)
	mockBundlestoreClient.
		EXPECT().
		UploadSBOM(gomock.Any(), gomock.Any()).
		Return("sbom-hash", nil).
		Times(1)

	originalClient := ostest.BundlestoreClient
	ostest.BundlestoreClient = mockBundlestoreClient
	t.Cleanup(func() { ostest.BundlestoreClient = originalClient })

	_, err := ostest.OSWorkflow(mockICTX, []workflow.Data{})
	require.NoError(t, err)
}

func TestSBOMTestWorkflow_Reachability_ExplicitPath_ContainsFiles(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	ctrlDep := gomock.NewController(t)
	defer ctrlDep.Finish()

	sourceCodePath := "testdata/test_dir"

	mockICTX := createMockInvocationCtxWithURL(t, ctrlDep, nil, mockServerURL)
	mockICTX.GetConfiguration().Set(flags.FlagReachability, true)
	mockICTX.GetConfiguration().Set(flags.FlagSBOM, "testdata/bom.json")
	mockICTX.GetConfiguration().Set(ostest.FeatureFlagSBOMTestReachability, true)
	mockICTX.GetConfiguration().Set("source-dir", sourceCodePath)

	mockBundlestoreClient := svcmocks.NewMockClient(ctrl)
	mockBundlestoreClient.
		EXPECT().
		UploadSourceCode(gomock.Any(), sourceCodePath).
		Return("source-code-hash", nil).
		Times(1)
	mockBundlestoreClient.
		EXPECT().
		UploadSBOM(gomock.Any(), gomock.Any()).
		Return("sbom-hash", nil).
		Times(1)

	originalClient := ostest.BundlestoreClient
	ostest.BundlestoreClient = mockBundlestoreClient
	t.Cleanup(func() { ostest.BundlestoreClient = originalClient })

	_, err := ostest.OSWorkflow(mockICTX, []workflow.Data{})
	require.NoError(t, err)
}

func TestSBOMTestWorkflow_Reachability_ExplicitPath_DoesntExist(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	ctrlDep := gomock.NewController(t)
	defer ctrlDep.Finish()

	sourceCodePath := "this/dir/does/not/exist"

	mockICTX := createMockInvocationCtxWithURL(t, ctrlDep, nil, mockServerURL)
	mockICTX.GetConfiguration().Set(flags.FlagReachability, true)
	mockICTX.GetConfiguration().Set(flags.FlagSBOM, "testdata/bom.json")
	mockICTX.GetConfiguration().Set(ostest.FeatureFlagSBOMTestReachability, true)
	mockICTX.GetConfiguration().Set("source-dir", sourceCodePath)

	mockBundlestoreClient := svcmocks.NewMockClient(ctrl)
	mockBundlestoreClient.
		EXPECT().
		UploadSourceCode(gomock.Any(), sourceCodePath).
		Return("source-code-hash", nil).
		Times(0)
	mockBundlestoreClient.
		EXPECT().
		UploadSBOM(gomock.Any(), gomock.Any()).
		Return("sbom-hash", nil).
		Times(0)

	originalClient := ostest.BundlestoreClient
	ostest.BundlestoreClient = mockBundlestoreClient
	t.Cleanup(func() { ostest.BundlestoreClient = originalClient })

	_, err := ostest.OSWorkflow(mockICTX, []workflow.Data{})
	errFactory := errors.NewErrorFactory(&logger)
	assert.Equal(t, errFactory.NewDirectoryDoesNotExistError(sourceCodePath), err)
}

func TestSBOMTestWorkflow_Reachability_ExplicitPath_Empty(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	ctrlDep := gomock.NewController(t)
	defer ctrlDep.Finish()

	sourceCodePath := t.TempDir()

	mockICTX := createMockInvocationCtxWithURL(t, ctrlDep, nil, mockServerURL)
	mockICTX.GetConfiguration().Set(flags.FlagReachability, true)
	mockICTX.GetConfiguration().Set(flags.FlagSBOM, "testdata/bom.json")
	mockICTX.GetConfiguration().Set(ostest.FeatureFlagSBOMTestReachability, true)
	mockICTX.GetConfiguration().Set("source-dir", sourceCodePath)

	mockBundlestoreClient := svcmocks.NewMockClient(ctrl)
	mockBundlestoreClient.
		EXPECT().
		UploadSourceCode(gomock.Any(), sourceCodePath).
		Return("source-code-hash", nil).
		Times(0)
	mockBundlestoreClient.
		EXPECT().
		UploadSBOM(gomock.Any(), gomock.Any()).
		Return("sbom-hash", nil).
		Times(0)

	originalClient := ostest.BundlestoreClient
	ostest.BundlestoreClient = mockBundlestoreClient
	t.Cleanup(func() { ostest.BundlestoreClient = originalClient })

	_, err := ostest.OSWorkflow(mockICTX, []workflow.Data{})
	errFactory := errors.NewErrorFactory(&logger)
	assert.Equal(t, errFactory.NewDirectoryIsEmptyError(sourceCodePath), err)
}
