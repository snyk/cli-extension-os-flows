package util

// Ptr returns a pointer to the given value.
//
//nolint:ireturn,nolintlint // rule doesn't get generics
func Ptr[T any](v T) *T {
	return &v
}
