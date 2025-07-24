package ostest_test

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/commands/ostest"
	"github.com/snyk/cli-extension-os-flows/internal/errors"
	"github.com/snyk/cli-extension-os-flows/internal/mocks"
)

//go:generate go run github.com/golang/mock/mockgen -package=mocks -destination=../../mocks/mock_codescanner.go github.com/snyk/code-client-go CodeScanner
//go:generate go run github.com/golang/mock/mockgen -package=mocks -destination=../../mocks/mock_bundlestore_client.go github.com/snyk/cli-extension-os-flows/internal/bundlestore Client

func Test_RunSbomReachabilityFlow_Success(t *testing.T) {
	logger := zerolog.Nop()
	ef := errors.NewErrorFactory(&logger)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	ctx := context.Background()
	sbomPath := "./testdata/bom.json"
	sourceCodePath := "./testdata/test_dir"

	mockBsClient := mocks.NewMockClient(ctrl)
	mockBsClient.EXPECT().UploadSBOM(ctx, sbomPath).Times(1)
	mockBsClient.EXPECT().UploadSourceCode(ctx, sourceCodePath).Times(1)

	_, err := ostest.RunSbomReachabilityFlow(context.Background(), ef, &logger, sbomPath, sourceCodePath, mockBsClient)

	require.NoError(t, err)
}
