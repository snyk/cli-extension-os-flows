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

func uploadDflySources(
	ctx context.Context,
	orgUUID uuid.UUID,
	clients FlowClients,
	inputDir string,
	opts *ReachabilityOpts,
) (resource *testapi.TestResourceCreateItem, policyFilesOnly bool, err error) {
	policyRoot := inputDir
	if opts != nil {
		if upload := uploadReachabilitySourcesIfAny(ctx, orgUUID, clients, opts, listsources.PolicyFileName); upload != nil {
			return upload, false, nil
		}
		policyRoot = opts.SourceDir
	}

	resource, err = uploadPolicyFilesIfAny(ctx, clients.FileUploadClient, policyRoot)
	return resource, resource != nil, err
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
