package npmsemver

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

	if r.satisfies, err = makeSatisfies(vm, mod); err != nil {
		return r, err
	}

	if r.valid, err = shared.MakeValidWithStringReturn(vm, mod); err != nil {
		return r, err
	}

	if r.prerelease, err = shared.MakePrerelease(vm, mod); err != nil {
		return r, err
	}

	return r, nil
}

func makeSatisfies(vm *goja.Runtime, mod map[string]any) (shared.SatisfiesFn, error) {
	funcObj, err := jscompat.GetFunction(mod, "satisfies")
	if err != nil {
		return nil, err
	}

	// includePrerelease overrides default behavior for prerelease tags.
	// https://github.com/npm/node-semver?tab=readme-ov-file#prerelease-tags
	options := vm.NewObject()
	if err := options.Set("includePrerelease", vm.ToValue(true)); err != nil {
		return nil, err
	}

	return func(version, versionRange string) bool {
		var result bool
		panicked := jscompat.Panicked(func() {
			result = funcObj(goja.FunctionCall{
				Arguments: []goja.Value{
					vm.ToValue(version),
					vm.ToValue(versionRange),
					options,
				},
			}).ToBoolean()
		})

		return panicked == nil && result
	}, nil
}
