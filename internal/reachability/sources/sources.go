// Package sources decides whether a directory is worth uploading for
// reachability analysis based purely on its contents.
package sources

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/snyk/go-application-framework/pkg/workflow"

	listsources "github.com/snyk/cli-extension-os-flows/internal/files"
)

// SupportedExtensionsByLanguage maps each reachability-supported language to
// the file extensions Code recognizes for it. Mirrors the corresponding subset
// of snyk/deepcode analysis/analysis_settings/analysis_settings.json (the
// authoritative source) and must be re-synced when Code adds extensions for
// Java/JS/TS/Python/C#. The public docs at
// https://docs.snyk.io/manage-risk/prioritize-issues-for-fixing/reachability-analysis
// list the supported languages but not the full extension set.
var SupportedExtensionsByLanguage = map[string][]string{
	"Java":                  {".java", ".jsp", ".jspx"},
	"JavaScript/TypeScript": {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".cts", ".mts", ".vue", ".htm", ".html", ".ejs", ".es", ".es6"},
	"Python":                {".py"},
	"C#":                    {".cs", ".aspx"},
}

var supportedExtensions = func() map[string]struct{} {
	m := make(map[string]struct{})
	for _, exts := range SupportedExtensionsByLanguage {
		for _, ext := range exts {
			m[ext] = struct{}{}
		}
	}
	return m
}()

// HasSupportedSources reports whether the given directory contains at least
// one file whose extension belongs to a language supported by reachability
// analysis. Callers must independently verify reachability is enabled for
// the org / feature flags before invoking this function — it only inspects
// the file tree.
func HasSupportedSources(ictx workflow.InvocationContext, path string) (bool, error) {
	if _, err := os.Stat(path); err != nil {
		return false, fmt.Errorf("failed to stat %s: %w", path, err)
	}

	logger := ictx.GetEnhancedLogger()

	files, err := listsources.ForPath(ictx, path, runtime.NumCPU())
	if err != nil {
		return false, fmt.Errorf("failed to list files in %s: %w", path, err)
	}

	for f := range files {
		if _, ok := supportedExtensions[filepath.Ext(f)]; ok {
			logger.Info().Str("extension", filepath.Ext(f)).Msg("supported extension found")
			unblockFileWalker(files)
			return true, nil
		}
	}
	return false, nil
}

// unblockFileWalker drains the remaining file paths in the background so the
// producer goroutines inside utils.FileFilter — which accept no context and
// cannot be canceled — can finish sending and exit cleanly after we've
// already found what we were looking for.
func unblockFileWalker(files <-chan string) {
	go func() {
		for range files { //nolint:revive // intentional drain to unblock producer
		}
	}()
}
