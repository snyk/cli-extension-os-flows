package common_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/cli-extension-os-flows/internal/common"
)

func TestProjectPolicyDir(t *testing.T) {
	const scanRoot, elsewhere = "/scan", "/elsewhere"

	tests := []struct {
		name              string
		inputDir          string
		displayTargetFile string
		want              string
	}{
		{
			name:              "single project in the scan root",
			inputDir:          "/scan",
			displayTargetFile: "package-lock.json",
			want:              "/scan",
		},
		{
			name:              "project one level down",
			inputDir:          "/scan",
			displayTargetFile: "proj-a/package-lock.json",
			want:              filepath.Join(scanRoot, "proj-a"),
		},
		{
			name:              "nested project",
			inputDir:          "/scan",
			displayTargetFile: "proj-a/packages/nested/package-lock.json",
			want:              filepath.Join(scanRoot, "proj-a", "packages", "nested"),
		},
		{
			name:              "no target file falls back to the scan root",
			inputDir:          "/scan",
			displayTargetFile: "",
			want:              "/scan",
		},
		{
			name:              "an absolute target file is used as-is",
			inputDir:          "/scan",
			displayTargetFile: "/elsewhere/proj-a/package-lock.json",
			want:              filepath.Join(elsewhere, "proj-a"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, common.ProjectPolicyDir(tt.inputDir, tt.displayTargetFile))
		})
	}
}
