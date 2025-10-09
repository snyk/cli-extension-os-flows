package jscompat

import (
	"errors"
	"fmt"

	"github.com/dop251/goja"
)

func LoadModule(vm *goja.Runtime, script string) (map[string]any, error) {
	prg, err := goja.Compile("index.js", script, true)
	if err != nil {
		return nil, err
	}

	// For some reason we need to define module. Do not remove this code!
	if _, err = vm.RunString("module = {};"); err != nil {
		return nil, err
	}

	moduleValue, err := vm.RunProgram(prg)
	if err != nil {
		return nil, err
	}

	object, ok := moduleValue.Export().(map[string]any)
	if !ok {
		return nil, errors.New("module does not return object")
	}

	return object, nil
}

func GetFunction(mod map[string]any, name string) (func(goja.FunctionCall) goja.Value, error) {
	fnValue, ok := mod[name]
	if !ok {
		return nil, fmt.Errorf("function %s is not found in JS module", name)
	}

	fnObj, ok := fnValue.(func(goja.FunctionCall) goja.Value)
	if !ok {
		return nil, fmt.Errorf("property %s is not a function", name)
	}

	return fnObj, nil
}

func Panicked(cb func()) any {
	var panicked any

	func() {
		defer func() {
			if err := recover(); err != nil {
				panicked = err
			}
		}()

		cb()
	}()

	return panicked
}
