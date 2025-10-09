package nodejsstubs

import (
	"fmt"
	"reflect"
	"slices"

	"github.com/dop251/goja"
)

func Assert(_ *goja.Runtime, object *goja.Object) {
	exports, ok := object.Get("exports").(*goja.Object)
	if !ok {
		panic("not a module export")
	}

	if err := exports.Set("strict", assertStrict); err != nil {
		panic(err)
	}
}

func assertStrict(call goja.FunctionCall) goja.Value {
	arg := call.Argument(0).Export()

	switch v := arg.(type) {
	case bool:
		if v {
			return nil
		}
	case int:
		if v != 0 {
			return nil
		}
	}

	kindsWithLen := []reflect.Kind{reflect.Array, reflect.Slice, reflect.Map, reflect.String}
	valueOf := reflect.ValueOf(arg)
	if slices.Contains(kindsWithLen, valueOf.Kind()) {
		if valueOf.Len() > 0 {
			return nil
		}
	}

	panic(fmt.Errorf("AssertionError: The expression evaluated to a falsy value %#v", arg))
}
