package common

import (
	"context"
	"time"

	"github.com/snyk/go-application-framework/pkg/apiclients/fileupload"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-os-flows/internal/deeproxy"
	"github.com/snyk/cli-extension-os-flows/internal/legacy/definitions"
	"github.com/snyk/cli-extension-os-flows/internal/reachability"
)

// PollInterval is the polling interval for the test API. It is exported to be configurable in tests.
var PollInterval = 2 * time.Second

// FlowClients encapsulates all the clients needed for running the flows.
type FlowClients struct {
	TestClient         testapi.TestClient
	FileUploadClient   fileupload.Client
	ReachabilityClient reachability.Client
	DeeproxyClient     deeproxy.Client
}

// ReachabilityOpts holds reachability-related settings for flows.
// If nil, reachability is not requested.
type ReachabilityOpts struct {
	SourceDir string
}

// RunTestWithResourcesFunc is the function signature for executing a test
// against the test API using uploaded resources. It decouples the dragonfly
// flow from the concrete test execution implementation.
type RunTestWithResourcesFunc func(
	ctx context.Context,
	targetDir string,
	testClient testapi.TestClient,
	resources []testapi.TestResourceCreateItem,
	projectName string,
	packageManager string,
	depCount int,
	targetFile string,
	displayTargetFile string,
	orgID string,
	testConfig *testapi.TestConfiguration,
) (*definitions.LegacyVulnerabilityResponse, []workflow.Data, error)
