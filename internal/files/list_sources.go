package listsources

import (
	"fmt"

	"github.com/snyk/go-application-framework/pkg/utils"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// ForPath returns a channel that notifies each file in the path that doesn't match the filter rules.
// The file filter comes from the invocation context, so it is already wired to the invocation's
// configuration and logger.
func ForPath(ictx workflow.InvocationContext, path string, maxThreads int) (<-chan string, error) {
	filter := ictx.GetFileFilter(path, utils.WithThreadNumber(maxThreads))
	rules, err := filter.GetRules([]string{".gitignore", ".dcignore", ".snyk"})
	if err != nil {
		return nil, fmt.Errorf("failed to get rules: %w", err)
	}

	results := filter.GetFilteredFiles(filter.GetAllFiles(), rules)
	return results, nil
}
