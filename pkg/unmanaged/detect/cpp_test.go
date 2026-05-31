package detect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHasCPPArtefacts(t *testing.T) {
	t.Run("empty root returns false", func(t *testing.T) {
		if HasCPPArtefacts("") {
			t.Fatal("expected false for empty root")
		}
	})

	t.Run("nonexistent root returns false", func(t *testing.T) {
		if HasCPPArtefacts(filepath.Join(t.TempDir(), "does-not-exist")) {
			t.Fatal("expected false for nonexistent root")
		}
	})

	t.Run("positive on .cpp file", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "main.cpp"), "int main(){}")
		if !HasCPPArtefacts(dir) {
			t.Fatal("expected true when .cpp file present")
		}
	})

	t.Run("positive on .h file in subdir", func(t *testing.T) {
		dir := t.TempDir()
		sub := filepath.Join(dir, "include")
		if err := os.Mkdir(sub, 0o700); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(sub, "lib.h"), "#pragma once")
		if !HasCPPArtefacts(dir) {
			t.Fatal("expected true when .h file present in subdir")
		}
	})

	t.Run("positive on CMakeLists.txt", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "CMakeLists.txt"), "project(x)")
		if !HasCPPArtefacts(dir) {
			t.Fatal("expected true when CMakeLists.txt present")
		}
	})

	t.Run("positive on .mk file", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "rules.mk"), "all:")
		if !HasCPPArtefacts(dir) {
			t.Fatal("expected true when *.mk present")
		}
	})

	t.Run("negative on pure JS project", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "package.json"), "{}")
		writeFile(t, filepath.Join(dir, "index.js"), "module.exports={}")
		if HasCPPArtefacts(dir) {
			t.Fatal("expected false when no C/C++ artefacts present")
		}
	})

	t.Run("ignores .cpp inside node_modules", func(t *testing.T) {
		dir := t.TempDir()
		nm := filepath.Join(dir, "node_modules")
		if err := os.Mkdir(nm, 0o700); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(nm, "binding.cpp"), "//")
		if HasCPPArtefacts(dir) {
			t.Fatal("node_modules must be skipped")
		}
	})

	t.Run("ignores .c inside cmake-build-debug", func(t *testing.T) {
		dir := t.TempDir()
		sub := filepath.Join(dir, "cmake-build-debug")
		if err := os.Mkdir(sub, 0o700); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(sub, "gen.c"), "//")
		if HasCPPArtefacts(dir) {
			t.Fatal("cmake-build-* must be skipped")
		}
	})

	t.Run("case-insensitive extension", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "Main.CPP"), "int main(){}")
		if !HasCPPArtefacts(dir) {
			t.Fatal("uppercase extensions should match")
		}
	})
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
