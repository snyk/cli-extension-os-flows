package ostest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/snyk/cli-extension-os-flows/internal/constants"
)

func TestAutoDetectEnabled(t *testing.T) {
	cases := []struct {
		name string
		val  string
		want bool
	}{
		{"unset", "", false},
		{"explicit false", "false", false},
		{"0", "0", false},
		{"true", "true", true},
		{"1", "1", true},
		{"garbage", "yesplease", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.val == "" {
				t.Setenv(constants.AutodetectOSSEnvVar, "")
				_ = os.Unsetenv(constants.AutodetectOSSEnvVar)
			} else {
				t.Setenv(constants.AutodetectOSSEnvVar, tc.val)
			}
			if got := autoDetectEnabled(); got != tc.want {
				t.Fatalf("autoDetectEnabled() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDetectCPPDirs(t *testing.T) {
	root := t.TempDir()
	cppDir := filepath.Join(root, "cpp-project")
	jsDir := filepath.Join(root, "js-project")
	if err := os.Mkdir(cppDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(jsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cppDir, "main.cpp"), []byte("int main(){}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(jsDir, "index.js"), []byte("module.exports={}"), 0o600); err != nil {
		t.Fatal(err)
	}

	got := detectCPPDirs([]string{cppDir, jsDir})
	if len(got) != 1 || got[0] != cppDir {
		t.Fatalf("detectCPPDirs = %v, want [%s]", got, cppDir)
	}
}

func TestContainsArg(t *testing.T) {
	if !containsArg([]string{"test", "--unmanaged"}, "--unmanaged") {
		t.Fatal("expected true when arg present")
	}
	if containsArg([]string{"test"}, "--unmanaged") {
		t.Fatal("expected false when arg absent")
	}
}
