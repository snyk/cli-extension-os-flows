package mavensemver

import (
	_ "embed"

	"github.com/dop251/goja"

	"github.com/snyk/cli-extension-os-flows/internal/semver/jscompat"
	"github.com/snyk/cli-extension-os-flows/internal/semver/shared"
)

//go:embed js/build/index.js
var jsScript string

type Runtime struct {
	compare    shared.CompareFn
	satisfies  shared.SatisfiesFn
	valid      shared.ValidFn
	prerelease shared.PrereleaseFn
}

func (r Runtime) Compare(lhs, rhs string) (int, error) {
	return r.compare(lhs, rhs)
}

func (r Runtime) Satisfies(version, versionRange string) bool {
	return r.satisfies(version, versionRange)
}

func (r Runtime) Valid(version string) string {
	return r.valid(version)
}

func (r Runtime) Prerelease(version string) []string {
	return r.prerelease(version)
}

func New() (Runtime, error) {
	var r Runtime

	vm := goja.New()

	mod, err := jscompat.LoadModule(vm, jsScript)
	if err != nil {
		return r, err
	}

	if r.compare, err = shared.MakeCompareFn(vm, mod); err != nil {
		return r, err
	}

	if r.satisfies, err = shared.MakeSatisfies(vm, mod); err != nil {
		return r, err
	}

	if r.valid, err = shared.MakeValidWithStringReturn(vm, mod); err != nil {
		return r, err
	}

	// Maven artifacts prerelease support not implemented yet, so we're returning nil
	r.prerelease = func(_ string) []string {
		return nil
	}

	return r, nil
}
