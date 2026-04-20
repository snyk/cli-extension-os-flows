package common_test

import (
	"testing"

	"github.com/snyk/cli-extension-dep-graph/pkg/identity"
	"github.com/snyk/dep-graph/go/pkg/depgraph"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/common"
	"github.com/snyk/cli-extension-os-flows/internal/util"
)

func TestBuildIdentity(t *testing.T) {
	t.Run("populates all fields from depgraph", func(t *testing.T) {
		dg := newDepGraph(t, "npm", "my-project@1.0.0", "my-project", "1.0.0")

		id := common.BuildIdentity(dg, &identity.ProjectDescriptor{
			Identity: identity.ProjectIdentity{
				Type:          "npm",
				TargetFile:    util.Ptr("proj/package.json"),
				TargetRuntime: util.Ptr("node@18.0.0"),
			},
		})

		assert.Equal(t, "my-project", id.Name)
		assert.Equal(t, "npm", id.Type)
		assert.Equal(t, "proj/package.json", id.TargetFile)
		require.NotNil(t, id.TargetRuntime)
		assert.Equal(t, "node@18.0.0", *id.TargetRuntime)
	})

	t.Run("empty runtime produces nil pointer", func(t *testing.T) {
		dg := newDepGraph(t, "npm", "proj@1.0.0", "proj", "1.0.0")

		id := common.BuildIdentity(dg, &identity.ProjectDescriptor{
			Identity: identity.ProjectIdentity{
				TargetRuntime: nil,
			},
		})

		assert.Nil(t, id.TargetRuntime)
	})

	t.Run("empty pkg manager", func(t *testing.T) {
		dg := newDepGraph(t, "", "app@2.0.0", "app", "2.0.0")

		id := common.BuildIdentity(dg, &identity.ProjectDescriptor{
			Identity: identity.ProjectIdentity{
				TargetFile: util.Ptr("pom.xml"),
			},
		})

		assert.Equal(t, "app", id.Name)
		assert.Equal(t, "", id.Type)
		assert.Equal(t, "pom.xml", id.TargetFile)
	})

	t.Run("nil depgraph", func(t *testing.T) {
		id := common.BuildIdentity(nil, &identity.ProjectDescriptor{
			Identity: identity.ProjectIdentity{
				TargetFile:    util.Ptr("some/path"),
				TargetRuntime: util.Ptr("python@3.11"),
			},
		})

		assert.Equal(t, "", id.Name)
		assert.Equal(t, "", id.Type)
		assert.Equal(t, "some/path", id.TargetFile)
		require.NotNil(t, id.TargetRuntime)
		assert.Equal(t, "python@3.11", *id.TargetRuntime)
	})

	t.Run("no root pkg", func(t *testing.T) {
		dg := &depgraph.DepGraph{
			SchemaVersion: "1.2.0",
			PkgManager:    depgraph.PkgManager{Name: "maven"},
			Pkgs:          []depgraph.Pkg{},
			Graph:         depgraph.Graph{RootNodeID: "root", Nodes: []depgraph.Node{}},
		}
		require.NoError(t, dg.BuildGraph())

		id := common.BuildIdentity(dg, &identity.ProjectDescriptor{
			Identity: identity.ProjectIdentity{
				Type:       "maven",
				TargetFile: util.Ptr("pom.xml"),
			},
		})

		assert.Equal(t, "", id.Name)
		assert.Equal(t, "maven", id.Type)
		assert.Equal(t, "pom.xml", id.TargetFile)
	})

	t.Run("empty target file", func(t *testing.T) {
		dg := newDepGraph(t, "pip", "mylib@0.1.0", "mylib", "0.1.0")

		id := common.BuildIdentity(dg, &identity.ProjectDescriptor{
			Identity: identity.ProjectIdentity{
				Type:          "pip",
				TargetRuntime: util.Ptr("python@3.11.0"),
			},
		})

		assert.Equal(t, "mylib", id.Name)
		assert.Equal(t, "pip", id.Type)
		assert.Equal(t, "", id.TargetFile)
		require.NotNil(t, id.TargetRuntime)
		assert.Equal(t, "python@3.11.0", *id.TargetRuntime)
	})
}

func newDepGraph(t *testing.T, pkgManager, rootID, rootName, rootVersion string) *depgraph.DepGraph {
	t.Helper()
	dg := &depgraph.DepGraph{
		SchemaVersion: "1.2.0",
		PkgManager:    depgraph.PkgManager{Name: pkgManager},
		Pkgs: []depgraph.Pkg{
			{ID: rootID, Info: depgraph.PkgInfo{Name: rootName, Version: rootVersion}},
		},
		Graph: depgraph.Graph{
			RootNodeID: "root",
			Nodes:      []depgraph.Node{{NodeID: "root", PkgID: rootID}},
		},
	}
	require.NoError(t, dg.BuildGraph())
	return dg
}
