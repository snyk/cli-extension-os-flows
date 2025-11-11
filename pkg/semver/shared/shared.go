package shared

import (
	"context"
	"fmt"

	"github.com/dop251/goja"
	"github.com/jackc/puddle/v2"

	"github.com/snyk/cli-extension-os-flows/pkg/semver/jscompat"
)

type (
	CompareFn func(lhs, rhs string) (int, error)
)

type Runtime interface {
	Compare(lhs, rhs string) (int, error)
}

type ConcurrentRuntime[R Runtime] struct {
	pool *puddle.Pool[R]
}

func NewConcurrentRuntime[R Runtime](newRuntime func() (R, error), workers int32) (ConcurrentRuntime[R], error) {
	pool, err := puddle.NewPool(&puddle.Config[R]{
		Constructor: func(context.Context) (R, error) { return newRuntime() },
		MaxSize:     workers,
	})

	return ConcurrentRuntime[R]{pool: pool}, err
}

func (r ConcurrentRuntime[R]) Compare(lhs, rhs string) (int, error) {
	vm, err := r.pool.Acquire(context.Background())
	if err != nil {
		return 0, err
	}
	defer vm.Release()

	return vm.Value().Compare(lhs, rhs)
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
