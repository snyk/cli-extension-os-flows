package rubysemver

import (
	_ "embed"

	"github.com/dop251/goja"

	"github.com/snyk/cli-extension-os-flows/pkg/semver/jscompat"
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

	mod, err := jscompat.LoadModule(vm, jsScript)
	if err != nil {
		return r, err
	}

	if r.compare, err = shared.MakeCompareFn(vm, mod); err != nil {
		return r, err
	}

	return r, nil
}
