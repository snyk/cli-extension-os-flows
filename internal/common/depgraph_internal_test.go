package common

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/identity"
	"github.com/snyk/dep-graph/go/pkg/depgraph"
	snyk_cli_errors "github.com/snyk/error-catalog-golang-public/cli"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/util"
)

func TestMapToRawDepGraphWithMeta_Success(t *testing.T) {
	dg := &depgraph.DepGraph{
		SchemaVersion: "1.2.0",
		PkgManager:    depgraph.PkgManager{Name: "npm"},
		Pkgs: []depgraph.Pkg{
			{ID: "proj@1.0.0", Info: depgraph.PkgInfo{Name: "proj", Version: "1.0.0"}},
		},
		Graph: depgraph.Graph{RootNodeID: "root"},
	}
	target := []byte(`{"remoteUrl":"https://github.com/acme/repo.git","branch":"main"}`)

	result := &ecosystems.SCAResult{
		DepGraph: dg,
		ProjectDescriptor: identity.ProjectDescriptor{
			Identity: identity.ProjectIdentity{
				TargetFile: util.Ptr("package.json"),
			},
		},
		ResolverMetadata: &ecosystems.ResolverMetadata{
			NormalisedTargetFile: "package.json",
		},
	}

	raw, err := mapToRawDepGraphWithMeta(result, target)

	require.NoError(t, err)

	var unmarshaled depgraph.DepGraph
	require.NoError(t, json.Unmarshal(raw.Payload, &unmarshaled))
	assert.Equal(t, "npm", unmarshaled.PkgManager.Name)

	assert.Equal(t, "package.json", raw.NormalisedTargetFile)
	require.NotNil(t, raw.TargetFileFromPlugin)
	assert.Equal(t, "package.json", *raw.TargetFileFromPlugin)
	assert.Equal(t, target, raw.Target)
}

func TestMapToRawDepGraphWithMeta_NilTargetFile(t *testing.T) {
	dg := &depgraph.DepGraph{
		SchemaVersion: "1.2.0",
		PkgManager:    depgraph.PkgManager{Name: "maven"},
	}

	result := &ecosystems.SCAResult{
		DepGraph: dg,
		ProjectDescriptor: identity.ProjectDescriptor{
			Identity: identity.ProjectIdentity{
				TargetFile: nil,
			},
		},
		ResolverMetadata: &ecosystems.ResolverMetadata{},
	}

	raw, err := mapToRawDepGraphWithMeta(result, nil)

	require.NoError(t, err)
	assert.Equal(t, "", raw.NormalisedTargetFile)
	assert.Nil(t, raw.TargetFileFromPlugin)
	assert.Nil(t, raw.Target)
}

func TestMapToRawDepGraphWithMeta_ResultError(t *testing.T) {
	result := &ecosystems.SCAResult{
		ProjectDescriptor: identity.ProjectDescriptor{
			Identity: identity.ProjectIdentity{
				TargetFile: util.Ptr("pom.xml"),
			},
		},
		Error: errors.New("resolution failed"),
	}

	_, err := mapToRawDepGraphWithMeta(result, nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to resolve depgraph for pom.xml")
	assert.ErrorContains(t, err, "resolution failed")
}

func TestAggregateResults_TimeoutDuringResolutionSurfacesDeadlineExceeded(t *testing.T) {
	results := make(chan ecosystems.SCAResult, 1)
	results <- ecosystems.SCAResult{Error: context.DeadlineExceeded}
	close(results)

	_, err := aggregateResults(nil, results, "/test/dir", nil, true)

	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)

	var snykErr snyk_errors.Error
	require.ErrorAs(t, err, &snykErr)
	assert.Equal(t, snyk_cli_errors.NewCommandTimeoutError("").ErrorCode, snykErr.ErrorCode)
}

func TestAggregateResults_TimeoutTakesPrecedenceOverPartialSuccess(t *testing.T) {
	results := make(chan ecosystems.SCAResult, 2)
	results <- ecosystems.SCAResult{
		ResolverMetadata: &ecosystems.ResolverMetadata{NormalisedTargetFile: "package.json"},
	}
	results <- ecosystems.SCAResult{Error: context.DeadlineExceeded}
	close(results)

	_, err := aggregateResults(nil, results, "/test/dir", nil, true)

	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)

	var snykErr snyk_errors.Error
	require.ErrorAs(t, err, &snykErr)
	assert.Equal(t, snyk_cli_errors.NewCommandTimeoutError("").ErrorCode, snykErr.ErrorCode)
}

func TestAggregateResults_NonTimeoutFailureKeepsGenericAllProjectsFailedMessage(t *testing.T) {
	results := make(chan ecosystems.SCAResult, 1)
	results <- ecosystems.SCAResult{Error: errors.New("boom")}
	close(results)

	_, err := aggregateResults(nil, results, "/test/dir", nil, true)

	require.Error(t, err)
	assert.False(t, errors.Is(err, context.DeadlineExceeded))
	assert.Contains(t, err.Error(), "failed to get dependencies for all 1 potential projects")
}

func TestAggregateResults_NoProjectsDetectedReturnsNoSupportedFilesFound(t *testing.T) {
	results := make(chan ecosystems.SCAResult)
	close(results)

	_, err := aggregateResults(nil, results, "/test/dir", nil, false)

	require.Error(t, err)

	var snykErr snyk_errors.Error
	require.ErrorAs(t, err, &snykErr)
	assert.Equal(t, snyk_cli_errors.NewNoSupportedFilesFoundError("").ErrorCode, snykErr.ErrorCode)
	assert.Contains(t, snykErr.Detail, "/test/dir")
}
