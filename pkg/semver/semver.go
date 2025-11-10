package semver

import (
	"fmt"
	"runtime"
	"sync"

	composersemver "github.com/snyk/cli-extension-os-flows/pkg/semver/composer"
	golangsemver "github.com/snyk/cli-extension-os-flows/pkg/semver/go"
	mavensemver "github.com/snyk/cli-extension-os-flows/pkg/semver/maven"
	npmsemver "github.com/snyk/cli-extension-os-flows/pkg/semver/npm"
	nugetsemver "github.com/snyk/cli-extension-os-flows/pkg/semver/nuget"
	rubysemver "github.com/snyk/cli-extension-os-flows/pkg/semver/ruby"
	"github.com/snyk/cli-extension-os-flows/pkg/semver/shared"
	unmanagedsemver "github.com/snyk/cli-extension-os-flows/pkg/semver/unmanaged"
)

var PoolSize = int32(runtime.NumCPU())

var (
	NPM = sync.OnceValues(func() (shared.Runtime, error) {
		return shared.NewConcurrentRuntime(npmsemver.New, PoolSize)
	})

	Ruby = sync.OnceValues(func() (shared.Runtime, error) {
		return shared.NewConcurrentRuntime(rubysemver.New, PoolSize)
	})

	Maven = sync.OnceValues(func() (shared.Runtime, error) {
		return shared.NewConcurrentRuntime(mavensemver.New, PoolSize)
	})

	Golang = sync.OnceValues(func() (shared.Runtime, error) {
		return shared.NewConcurrentRuntime(golangsemver.New, PoolSize)
	})

	Composer = sync.OnceValues(func() (shared.Runtime, error) {
		return shared.NewConcurrentRuntime(composersemver.New, PoolSize)
	})

	Nuget = sync.OnceValues(func() (shared.Runtime, error) {
		return shared.NewConcurrentRuntime(nugetsemver.New, PoolSize)
	})

	Unmanaged = sync.OnceValues(func() (shared.Runtime, error) {
		return shared.NewConcurrentRuntime(unmanagedsemver.New, PoolSize)
	})
)

func GetSemver(pkgManager string) (shared.Runtime, error) {
	switch pkgManager {
	case "npm", "yarn", "yarn-workspace", "pnpm",
		"cargo",
		"hex",
		"pub",
		"swift":
		return NPM()
	case "rubygems", "cocoapods":
		return Ruby()
	case "composer":
		return Composer()
	case "maven", "gradle", "sbt",
		"pip", "poetry", "pipenv":
		return Maven()
	case "nuget", "packet":
		return Nuget()
	case "golang", "golangdep", "govendor", "gomodules":
		return Golang()
	case "unmanaged", "cpp", "conan":
		return Unmanaged()
	default:
		return nil, fmt.Errorf("no semver library defined for ecosystem: %s", pkgManager)
	}
}
