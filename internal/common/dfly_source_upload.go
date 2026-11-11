package common

import (
	"context"
	"fmt"
	"runtime"

	"github.com/google/uuid"
	"github.com/snyk/go-application-framework/pkg/apiclients/fileupload"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"

	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	listsources "github.com/snyk/cli-extension-os-flows/internal/files"
)

type UploadResult struct {
	resource           *testapi.TestResourceCreateItem
	sourceCodeUploaded bool
}

func uploadDflySources(
	ctx context.Context,
	orgUUID uuid.UUID,
	clients FlowClients,
	inputDir string,
	opts *ReachabilityOpts,
) (result UploadResult, err error) {
	reachabilityRequested := opts != nil

	if reachabilityRequested {
		return uploadReachabilitySourcesIfAny(ctx, orgUUID, clients, opts, listsources.PolicyFileName)
	}

	resource, err := uploadPolicyFilesIfAny(ctx, clients.FileUploadClient, inputDir)
	return UploadResult{resource: resource, sourceCodeUploaded: false}, err
}

func uploadPolicyFilesIfAny(ctx context.Context, fc fileupload.Client, dir string) (*testapi.TestResourceCreateItem, error) {
	policyFiles, err := listsources.PolicyFilesForPath(cmdctx.Ictx(ctx), dir, runtime.NumCPU())
	if err != nil {
		return nil, fmt.Errorf("failed to find .snyk policy files: %w", err)
	}
	if len(policyFiles) == 0 {
		return nil, nil //nolint:nilnil // No .snyk files means no resource, which is not an error.
	}

	cmdctx.Logger(ctx).Debug().Strs("policy_files", policyFiles).Msg("Uploading .snyk policy files")
	resource, err := UploadPolicyFilesResource(ctx, fc, dir, policyFiles)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}
