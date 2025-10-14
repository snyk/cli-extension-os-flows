package utils

import (
	"fmt"
	"strings"
)

// JoinNameAndVersion will join a package name and version with an `@`.
func JoinNameAndVersion(name, version string) string {
	return fmt.Sprintf("%s@%s", name, version)
}

// SplitNameAndVersion will split a package string into it's name and version.
func SplitNameAndVersion(p string) (name, version string) {
	idx := strings.LastIndex(p, "@")
	return p[:idx], p[idx+1:]
}
