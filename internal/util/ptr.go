package util

// Ptr returns a pointer to the given value.
//
//nolint:ireturn,nolintlint // rule doesn't get generics
func Ptr[T any](v T) *T {
	return &v
}

// DefaultValue takes a pointer value and a fallback, and returns
// the fallback if the pointer value is nil.
func DefaultValue[T any](val *T, fallback T) T {
	if val == nil {
		return fallback
	}
	return *val
}

// PtrOrNil returns a pointer to the string, or nil if the string is empty.
// This is useful for optional JSON fields with omitempty.
func PtrOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
