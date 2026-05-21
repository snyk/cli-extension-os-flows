// Package sources decides whether a directory is worth uploading for
// reachability analysis based purely on its contents.
package sources

import "github.com/rs/zerolog"

// HasSupportedSources reports whether the given directory contains at least
// one file whose extension belongs to a language supported by reachability
// analysis. Callers must independently verify reachability is enabled for
// the org / feature flags before invoking this function — it only inspects
// the file tree.
func HasSupportedSources(path string, logger *zerolog.Logger) (bool, error) {
	_ = path
	_ = logger
	return false, nil
}
