// Package detect inspects a directory tree to decide whether it looks like
// a C/C++ project that the unmanaged OSS scanner can handle.
//
// The detector is purposely conservative and fast: it short-circuits on the
// first matching file and is bounded by file-count and depth limits so it is
// safe to call on the hot path of every OSS scan.
package detect

import (
	"io/fs"
	"path/filepath"
	"strings"
)

const (
	// maxFiles caps how many filesystem entries the walker will examine before
	// giving up. Tuned so the walk fits comfortably in single-digit ms even on
	// a cold cache, and bounds worst-case latency on pathological trees.
	maxFiles = 5000
	// maxDepth caps how deep the walker descends below root. Most C/C++ source
	// lives within a few levels; deeply nested vendor trees rarely contain
	// project-defining artefacts.
	maxDepth = 6
)

var cppFileExtensions = map[string]bool{
	".c":   true,
	".cc":  true,
	".cpp": true,
	".cxx": true,
	".c++": true,
	".h":   true,
	".hh":  true,
	".hpp": true,
	".hxx": true,
	".h++": true,
	".ipp": true,
	".tpp": true,
	".tcc": true,
	".inl": true,
}

var cppArtefactNames = map[string]bool{
	"CMakeLists.txt": true,
	"Makefile":       true,
	"makefile":       true,
	"configure.ac":   true,
	"configure.in":   true,
	"meson.build":    true,
}

var skipDirNames = map[string]bool{
	".git":             true,
	".svn":             true,
	".hg":              true,
	".idea":            true,
	".vscode":          true,
	"node_modules":     true,
	"vendor":           true,
	"bower_components": true,
	"dist":             true,
	"build":            true,
	"out":              true,
	"target":           true,
}

// HasCPPArtefacts walks root looking for any C/C++ source, header, or
// build-system file. It short-circuits on the first hit and is bounded by
// maxFiles and maxDepth so it is safe to call on the hot path of an OSS scan.
// Returns false if root is empty, does not exist, or is unreadable.
func HasCPPArtefacts(root string) bool {
	if root == "" {
		return false
	}
	seen := 0
	found := false
	rootDepth := strings.Count(filepath.Clean(root), string(filepath.Separator))

	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || found || seen >= maxFiles {
			return fs.SkipAll
		}
		seen++

		if d.IsDir() {
			if path == root {
				return nil
			}
			name := d.Name()
			// cmake-build-* are generated trees that contain copies of the
			// source plus build artefacts — skip to avoid double-counting and
			// to keep the walk small.
			if skipDirNames[name] || strings.HasPrefix(name, "cmake-build-") {
				return fs.SkipDir
			}
			depth := strings.Count(filepath.Clean(path), string(filepath.Separator)) - rootDepth
			if depth > maxDepth {
				return fs.SkipDir
			}
			return nil
		}

		name := d.Name()
		if cppArtefactNames[name] {
			found = true
			return fs.SkipAll
		}
		if strings.HasSuffix(name, ".mk") {
			found = true
			return fs.SkipAll
		}
		ext := strings.ToLower(filepath.Ext(name))
		if cppFileExtensions[ext] {
			found = true
			return fs.SkipAll
		}
		return nil
	})

	return found
}
