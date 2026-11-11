package common

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"

	"github.com/google/uuid"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
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

	if reachabilityRequested {
		warnIfSourceDirIsIgnored(ctx, inputDir, opts.SourceDir)
		upload, err := uploadReachabilitySourcesIfAny(ctx, orgUUID, clients, &ReachabilityOpts{SourceDir: inputDir}, listsources.PolicyFileName)
		if err != nil {
			return upload, err
		}
		if upload.resource != nil {
			return upload, nil
		}
	}

	resource, err := uploadPolicyFilesIfAny(ctx, clients.FileUploadClient, inputDir)
	return UploadResult{resource: resource, sourceCodeUploaded: false}, err
}

func warnIfSourceDirIsIgnored(ctx context.Context, inputDir, sourceDir string) {
	if absolutePath(sourceDir) == absolutePath(inputDir) {
		return
	}
	//nolint:errcheck // Best-effort warning output.
	cmdctx.Ictx(ctx).GetUserInterface().OutputError(snyk_errors.Error{
		Title:  "--source-dir is ignored",
		Detail: fmt.Sprintf("test and monitor upload the sources in %s, not in %s.", inputDir, sourceDir),
		Level:  "warn",
	})
}

func absolutePath(path string) string {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return filepath.Clean(path)
	}
	return absolute
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
