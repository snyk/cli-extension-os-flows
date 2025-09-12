package semver

import (
	"fmt"
	"sync"

	mavensemver "github.com/snyk/cli-extension-os-flows/internal/semver/maven"
	npmsemver "github.com/snyk/cli-extension-os-flows/internal/semver/npm"
	rubysemver "github.com/snyk/cli-extension-os-flows/internal/semver/ruby"
	"github.com/snyk/cli-extension-os-flows/internal/semver/shared"
)

var (
	NPM = sync.OnceValues(func() (shared.Runtime, error) {
		return npmsemver.New()
	})

	Ruby = sync.OnceValues(func() (shared.Runtime, error) {
		return rubysemver.New()
	})

	Maven = sync.OnceValues(func() (shared.Runtime, error) {
		return mavensemver.New()
	})
)

func GetSemver(ecosystem string) (shared.Runtime, error) {
	switch ecosystem {
	case "npm", "yarn", "pnpm", "yarn-workspace", "swift":
		return NPM()
	case "rubygems", "cocoapods":
		return Ruby()
	case "maven", "gradle", "sbt", "pip", "poetry", "pipenv", "nuget":
		return Maven()
	default:
		return nil, fmt.Errorf("no semver library defined for ecosystem: %s", ecosystem)
	}
}
