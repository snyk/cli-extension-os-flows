package nodejsstubs

import (
	"testing"

	"github.com/dop251/goja"
	gojarequire "github.com/dop251/goja_nodejs/require"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAssert(t *testing.T) {
	type testCase struct {
		value         any
		panicTestFunc func(t assert.TestingT, f assert.PanicTestFunc, _ ...interface{}) bool
	}

	tests := []testCase{
		{value: nil, panicTestFunc: assert.Panics},
		{value: []string{}, panicTestFunc: assert.Panics},
		{value: []any{}, panicTestFunc: assert.Panics},
		{value: "", panicTestFunc: assert.Panics},
		{value: 0, panicTestFunc: assert.Panics},
		{value: false, panicTestFunc: assert.Panics},
		{value: true, panicTestFunc: assert.NotPanics},
		{value: 1, panicTestFunc: assert.Panics},
		{value: []string{"hello"}, panicTestFunc: assert.NotPanics},
		{value: []any{"hello"}, panicTestFunc: assert.NotPanics},
		{value: "hello", panicTestFunc: assert.NotPanics},
	}

	testFn := makeAssertFn(t)

	for _, tc := range tests {
		t.Run("", func(t *testing.T) {
			tc.panicTestFunc(t, func() {
				testFn(tc.value)
			})
		})
	}
}

func makeAssertFn(t *testing.T) func(value any) {
	t.Helper()

	vm := goja.New()

	gojarequire.RegisterCoreModule("assert", Assert)
	gojarequire.NewRegistry().Enable(vm)

	script := `const assert = require('node:assert').strict;
function assert_fn(value) { assert(value); }`
	_, err := vm.RunScript("test.js", script)
	require.NoError(t, err)

	funcObj, ok := vm.Get("assert_fn").Export().(func(goja.FunctionCall) goja.Value)
	require.True(t, ok)

	return func(value any) {
		funcObj(goja.FunctionCall{
			Arguments: []goja.Value{
				vm.ToValue(value),
			},
		})
	}
}
