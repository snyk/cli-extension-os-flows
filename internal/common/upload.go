package common

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/snyk/go-application-framework/pkg/apiclients/fileupload"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"

	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	"github.com/snyk/cli-extension-os-flows/internal/deeproxy"
	"github.com/snyk/cli-extension-os-flows/internal/reachability"
)

// UploadSourceCodeResource uploads source code and creates the test resource.
func UploadSourceCodeResource(
	ctx context.Context,
	orgID uuid.UUID,
	fc fileupload.Client,
	dc deeproxy.Client,
	sourceCodePath string,
) (testapi.TestResourceCreateItem, error) {
	logger := cmdctx.Logger(ctx)

	sourceResult, err := reachability.UploadSourceCode(ctx, orgID, fc, dc, sourceCodePath)
	if err != nil {
		logger.Error().Err(err).Str("sourceCodePath", sourceCodePath).Msg("Failed to upload source code")
		return testapi.TestResourceCreateItem{}, fmt.Errorf("failed to upload source code: %w", err)
	}
	logger.Debug().Str("sourceRevisionID", sourceResult.RevisionID.String()).Msg("Source code uploaded successfully")

	return NewUploadResource(sourceResult.RevisionID.String(), testapi.UploadResourceContentTypeSource, nil)
}

// NewUploadResource creates a TestResourceCreateItem from a revision ID, content type, and optional SCM context.
func NewUploadResource(revisionID string, contentType testapi.UploadResourceContentType, scmCtx *testapi.ScmContext) (testapi.TestResourceCreateItem, error) {
	uploadResource := testapi.UploadResource{
		ContentType:  contentType,
		FilePatterns: []string{},
		RevisionId:   revisionID,
		Type:         testapi.Upload,
		ScmContext:   scmCtx,
	}

	var resourceVariant testapi.BaseResourceVariantCreateItem
	if err := resourceVariant.FromUploadResource(uploadResource); err != nil {
		return testapi.TestResourceCreateItem{}, fmt.Errorf("failed to create resource variant: %w", err)
	}

	baseResource := testapi.BaseResourceCreateItem{
		Resource: resourceVariant,
		Type:     testapi.BaseResourceCreateItemTypeBase,
	}

	var testResource testapi.TestResourceCreateItem
	if err := testResource.FromBaseResourceCreateItem(baseResource); err != nil {
		return testapi.TestResourceCreateItem{}, fmt.Errorf("failed to create test resource: %w", err)
	}

	return testResource, nil
}
