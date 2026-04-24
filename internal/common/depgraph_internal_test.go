package common

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/pkg/identity"
	"github.com/snyk/dep-graph/go/pkg/depgraph"
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
