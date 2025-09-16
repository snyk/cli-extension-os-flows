package shared

import (
	"fmt"

	"github.com/dop251/goja"

	"github.com/snyk/cli-extension-os-flows/internal/semver/jscompat"
)

type (
	CompareFn    func(lhs, rhs string) (int, error)
	SatisfiesFn  func(version, versionRange string) bool
	ValidFn      func(version string) string
	PrereleaseFn func(version string) []string
)

type Runtime interface {
	Compare(lhs, rhs string) (int, error)
	Satisfies(version, versionRange string) bool
	Valid(version string) string
	Prerelease(version string) []string
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

func MakeSatisfies(vm *goja.Runtime, mod map[string]any) (SatisfiesFn, error) {
	funcObj, err := jscompat.GetFunction(mod, "satisfies")
	if err != nil {
		return nil, err
	}

	return func(version, versionRange string) bool {
		var result bool
		panicked := jscompat.Panicked(func() {
			result = funcObj(goja.FunctionCall{
				Arguments: []goja.Value{
					vm.ToValue(version),
					vm.ToValue(versionRange),
				},
			}).ToBoolean()
		})

		return panicked == nil && result
	}, nil
}

func MakeValidWithBoolReturn(vm *goja.Runtime, mod map[string]any) (ValidFn, error) {
	funcObj, err := jscompat.GetFunction(mod, "valid")
	if err != nil {
		return nil, err
	}

	return func(version string) string {
		var result bool
		panicked := jscompat.Panicked(func() {
			result = funcObj(goja.FunctionCall{
				Arguments: []goja.Value{
					vm.ToValue(version),
				},
			}).ToBoolean()
		})

		if panicked != nil || !result {
			return ""
		}

		return version
	}, nil
}

func MakeValidWithStringReturn(vm *goja.Runtime, mod map[string]any) (ValidFn, error) {
	funcObj, err := jscompat.GetFunction(mod, "valid")
	if err != nil {
		return nil, err
	}

	return func(version string) string {
		var result string
		panicked := jscompat.Panicked(func() {
			result, _ = funcObj(goja.FunctionCall{
				Arguments: []goja.Value{
					vm.ToValue(version),
				},
			}).Export().(string)
		})

		if panicked != nil {
			return ""
		}

		return result
	}, nil
}

func MakePrerelease(vm *goja.Runtime, mod map[string]any) (PrereleaseFn, error) {
	funcObj, err := jscompat.GetFunction(mod, "prerelease")
	if err != nil {
		return nil, err
	}

	return func(version string) []string {
		var result []string
		panicked := jscompat.Panicked(func() {
			jsResult := funcObj(goja.FunctionCall{
				Arguments: []goja.Value{
					vm.ToValue(version),
				},
			})

			// The JavaScript prerelease function returns null for non-prerelease versions
			// or an array of prerelease components for prerelease versions
			if jsResult != nil && !goja.IsNull(jsResult) && !goja.IsUndefined(jsResult) {
				if exported := jsResult.Export(); exported != nil {
					if arr, ok := exported.([]interface{}); ok {
						result = make([]string, len(arr))
						for i, v := range arr {
							result[i] = fmt.Sprintf("%v", v)
						}
					}
				}
			}
		})

		if panicked != nil {
			return nil
		}

		return result
	}, nil
}
