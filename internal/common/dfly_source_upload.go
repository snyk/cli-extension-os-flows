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

// UploadResult is the source resource of a test, if any, and whether it holds source code for
// reachability analysis.
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
) (UploadResult, error) {
	reachabilityRequested := opts != nil
	policyDir := inputDir

	if reachabilityRequested {
		upload, err := uploadReachabilitySourcesIfAny(ctx, orgUUID, clients, opts, listsources.PolicyFileName)
		if err != nil {
			return upload, err
		}
		if upload.resource != nil {
			return upload, nil
		}
		policyDir = opts.SourceDir
	}

	resource, err := uploadPolicyFilesIfAny(ctx, clients.FileUploadClient, policyDir)
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
