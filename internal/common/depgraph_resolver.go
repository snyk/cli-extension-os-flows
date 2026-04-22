package common

import (
	"fmt"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/orchestrator"
	"github.com/snyk/cli-extension-dep-graph/pkg/identity"
	"github.com/snyk/dep-graph/go/pkg/depgraph"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-os-flows/internal/util"
)

// Identity holds the fields required to determine a project's identity.
type Identity struct {
	Name string `json:"name"`
	Type string `json:"type"`
	// Do we need the relative one as well?
	TargetFile    string  `json:"targetFile"`
	TargetRuntime *string `json:"targetRuntime"`
}

// DepgraphWithIdentity holds a dependency graphs and its associated identity information.
type DepgraphWithIdentity struct {
	DepGraph *depgraph.DepGraph `json:"depGraph"`
	Identity Identity           `json:"identity"`
}

// BuildIdentity constructs an Identity from a project descriptor.
func BuildIdentity(projDesc *identity.ProjectDescriptor) Identity {
	return Identity{
		TargetFile:    util.DefaultValue(projDesc.Identity.TargetFile, ""),
		TargetRuntime: projDesc.Identity.TargetRuntime,
		Type:          projDesc.Identity.ProjectType,
		Name:          projDesc.Identity.RootComponentName,
	}
}

type depgraphResolver struct{}

// DepgraphResolver is the interface for resolving dependency graphs with their associated identities.
type DepgraphResolver interface {
	GetDepGraphsWithIdentity(ictx workflow.InvocationContext, inputDir string) ([]DepgraphWithIdentity, error)
}

// NewDepgraphResolver creates a new DepgraphResolver.
func NewDepgraphResolver() DepgraphResolver {
	return &depgraphResolver{}
}

// GetDepGraphsWithIdentity retrieves the dependency graphs for the given invocation context and input directory
// using the ecosystems orchestrator.
func (dr *depgraphResolver) GetDepGraphsWithIdentity(ictx workflow.InvocationContext, inputDir string) ([]DepgraphWithIdentity, error) {
	config := ictx.GetConfiguration()
	logger := ictx.GetEnhancedLogger()

	rawFlags := config.GetStringSlice(configuration.RAW_CMD_ARGS)
	opts, err := ecosystems.NewPluginOptionsFromRawFlags(rawFlags)
	if err != nil {
		return nil, fmt.Errorf("failed to convert raw flags to options: %w", err)
	}

	logger.Info().Msgf("invoking ecosystems orchestrator with raw flags: %s", rawFlags)
	results, err := orchestrator.ResolveDepgraphs(ictx, inputDir, *opts)
	if err != nil {
		return nil, fmt.Errorf("failed to resolved dependency graphs: %w", err)
	}

	dgs := make([]DepgraphWithIdentity, 0)
	for res := range results {
		if res.Error != nil {
			return nil, res.Error
		}
		dgs = append(dgs, DepgraphWithIdentity{
			DepGraph: res.DepGraph,
			Identity: BuildIdentity(&res.ProjectDescriptor),
		})
	}

	logger.Info().Msgf("generated %d dependency graph(s)", len(dgs))
	return dgs, nil
}
