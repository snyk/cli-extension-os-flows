// Package sources decides whether a directory is worth uploading for
// reachability analysis based purely on its contents.
package sources

import (
	"fmt"
	"path/filepath"
	"runtime"

	"github.com/rs/zerolog"

	listsources "github.com/snyk/cli-extension-os-flows/internal/files"
)

// supportedExtensions is the curated set of file extensions that belong to a
// reachability-supported language. Mirrors
// https://docs.snyk.io/manage-risk/prioritize-issues-for-fixing/reachability-analysis
// and must be kept in sync manually when reachability adds a language.
// Verify against the registry and sast-analysis-api definitions before extending.
var supportedExtensions = map[string]struct{}{
	".java": {},
	".js":   {},
	".jsx":  {},
	".mjs":  {},
	".cjs":  {},
	".ts":   {},
	".tsx":  {},
	".py":   {},
	".cs":   {},
}

// HasSupportedSources reports whether the given directory contains at least
// one file whose extension belongs to a language supported by reachability
// analysis. Callers must independently verify reachability is enabled for
// the org / feature flags before invoking this function — it only inspects
// the file tree.
func HasSupportedSources(path string, logger *zerolog.Logger) (bool, error) {
	files, err := listsources.ForPath(path, logger, runtime.NumCPU())
	if err != nil {
		return false, fmt.Errorf("failed to list files in %s: %w", path, err)
	}

	for f := range files {
		if _, ok := supportedExtensions[filepath.Ext(f)]; ok {
			unblockFileWalker(files)
			return true, nil
		}
	}
	return false, nil
}

// unblockFileWalker drains the remaining file paths in the background so the
// producer goroutines inside utils.FileFilter — which accept no context and
// cannot be cancelled — can finish sending and exit cleanly after we've
// already found what we were looking for.
func unblockFileWalker(files <-chan string) {
	go func() {
		for range files {
		}
	}()
}
