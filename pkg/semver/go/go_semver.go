package gosemver

import (
	_ "embed"

	"github.com/dop251/goja"
	"github.com/dop251/goja_nodejs/require"

	"github.com/snyk/cli-extension-os-flows/pkg/semver/jscompat"
	"github.com/snyk/cli-extension-os-flows/pkg/semver/jscompat/nodejsstubs"
	"github.com/snyk/cli-extension-os-flows/pkg/semver/shared"
)

//go:embed js/build/index.js
var jsScript string

type Runtime struct {
	compare shared.CompareFn
}

func (r Runtime) Compare(lhs, rhs string) (int, error) {
	return r.compare(lhs, rhs)
}

func New() (Runtime, error) {
	var r Runtime

	vm := goja.New()

	registry := require.NewRegistry()
	registry.RegisterNativeModule("assert", nodejsstubs.Assert)
	registry.Enable(vm)

	mod, err := jscompat.LoadModule(vm, jsScript)
	if err != nil {
		return r, err
	}

	if r.compare, err = shared.MakeCompareFn(vm, mod); err != nil {
		return r, err
	}

	return r, nil
}
