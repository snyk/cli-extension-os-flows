package shared

import (
	"fmt"

	"github.com/dop251/goja"

	"github.com/snyk/cli-extension-os-flows/pkg/semver/jscompat"
)

type (
	CompareFn func(lhs, rhs string) (int, error)
)

type Runtime interface {
	Compare(lhs, rhs string) (int, error)
}

func MakeCompareFn(vm *goja.Runtime, mod map[string]any) (CompareFn, error) {
	funcObj, err := jscompat.GetFunction(mod, "compare")
	if err != nil {
		return nil, err
	}

	return func(lhs, rhs string) (int, error) {
		var result int64
		panicked := jscompat.Panicked(func() {
			result = funcObj(goja.FunctionCall{
				Arguments: []goja.Value{
					vm.ToValue(lhs),
					vm.ToValue(rhs),
				},
			}).ToInteger()
		})

		if panicked != nil {
			return 0, fmt.Errorf("compare panicked: %v", panicked)
		}

		return int(result), nil
	}, nil
}
