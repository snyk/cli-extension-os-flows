package listsources

import (
	"fmt"
	"path/filepath"

	"github.com/snyk/go-application-framework/pkg/utils"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// PolicyFileName is the file name of a Snyk local policy.
const PolicyFileName = ".snyk"

// ForPath returns a channel that notifies each file in the path that doesn't match the filter rules.
func ForPath(ictx workflow.InvocationContext, path string, maxThreads int) (<-chan string, error) {
	filter := ictx.GetFileFilter(path, utils.WithThreadNumber(maxThreads))
	rules, err := filter.GetRules([]string{".gitignore", ".dcignore", ".snyk"})
	if err != nil {
		return nil, fmt.Errorf("failed to get rules: %w", err)
	}

	results := filter.GetFilteredFiles(filter.GetAllFiles(), rules)
	return results, nil
}

// PolicyFilesForPath returns the .snyk files in path and its subfolders, leaving out any
// that the .gitignore, .dcignore or .snyk exclude rules filter away.
func PolicyFilesForPath(ictx workflow.InvocationContext, path string, maxThreads int) ([]string, error) {
	files, err := ForPath(ictx, path, maxThreads)
	if err != nil {
		return nil, err
	}

	var policyFiles []string
	for file := range files {
		if filepath.Base(file) == PolicyFileName {
			policyFiles = append(policyFiles, file)
		}
	}
	return policyFiles, nil
}
