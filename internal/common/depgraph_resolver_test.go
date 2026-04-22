package common_test

import (
	"testing"

	"github.com/snyk/cli-extension-dep-graph/pkg/identity"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/common"
	"github.com/snyk/cli-extension-os-flows/internal/util"
	"github.com/snyk/cli-extension-os-flows/pkg/flags"
)

func TestBuildIdentity(t *testing.T) {
	t.Run("populates all fields from project descriptor", func(t *testing.T) {
		cfg := configuration.New()
		id := common.BuildIdentity(cfg, &identity.ProjectDescriptor{
			Identity: identity.ProjectIdentity{
				ProjectType:       "npm",
				TargetFile:        util.Ptr("proj/package.json"),
				TargetRuntime:     util.Ptr("node@18.0.0"),
				RootComponentName: "my-project",
			},
		})

		assert.Equal(t, "my-project", id.Name)
		assert.Equal(t, "npm", id.Type)
		assert.Equal(t, "proj/package.json", id.TargetFile)
		require.NotNil(t, id.TargetRuntime)
		assert.Equal(t, "node@18.0.0", *id.TargetRuntime)
	})

	t.Run("empty runtime produces nil pointer", func(t *testing.T) {
		cfg := configuration.New()
		id := common.BuildIdentity(cfg, &identity.ProjectDescriptor{
			Identity: identity.ProjectIdentity{
				TargetRuntime: nil,
			},
		})

		assert.Nil(t, id.TargetRuntime)
	})

	t.Run("empty project type", func(t *testing.T) {
		cfg := configuration.New()
		id := common.BuildIdentity(cfg, &identity.ProjectDescriptor{
			Identity: identity.ProjectIdentity{
				TargetFile:        util.Ptr("pom.xml"),
				ProjectType:       "",
				RootComponentName: "app",
			},
		})

		assert.Equal(t, "app", id.Name)
		assert.Equal(t, "", id.Type)
		assert.Equal(t, "pom.xml", id.TargetFile)
	})

	t.Run("no root component", func(t *testing.T) {
		cfg := configuration.New()
		id := common.BuildIdentity(cfg, &identity.ProjectDescriptor{
			Identity: identity.ProjectIdentity{
				ProjectType:       "maven",
				TargetFile:        util.Ptr("pom.xml"),
				RootComponentName: "",
			},
		})

		assert.Equal(t, "", id.Name)
		assert.Equal(t, "maven", id.Type)
		assert.Equal(t, "pom.xml", id.TargetFile)
	})

	t.Run("empty target file", func(t *testing.T) {
		cfg := configuration.New()
		id := common.BuildIdentity(cfg, &identity.ProjectDescriptor{
			Identity: identity.ProjectIdentity{
				ProjectType:       "pip",
				TargetRuntime:     util.Ptr("python@3.11.0"),
				RootComponentName: "mylib",
			},
		})

		assert.Equal(t, "mylib", id.Name)
		assert.Equal(t, "pip", id.Type)
		assert.Equal(t, "", id.TargetFile)
		require.NotNil(t, id.TargetRuntime)
		assert.Equal(t, "python@3.11.0", *id.TargetRuntime)
	})

	t.Run("project name overrides root component name", func(t *testing.T) {
		cfg := configuration.New()
		cfg.Set(flags.FlagProjectName, "my-project")
		id := common.BuildIdentity(cfg, &identity.ProjectDescriptor{
			Identity: identity.ProjectIdentity{
				RootComponentName: "mylib",
			},
		})

		assert.Equal(t, "my-project", id.Name)
	})
}
