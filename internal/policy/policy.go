package policy

import (
	"fmt"
	"os"
	"path"
)

const policyFileName = ".snyk"

// Resolve resolves to a snyk policy file. The given path can either point at
// a policy file or a directory which contains a .snyk file. If no policy
// is found at the given location, an error is returned.
func Resolve(dirOrFile string) (*os.File, error) {
	fp := dirOrFile

	// if a directory was given, add the expected policy file name.
	info, err := os.Stat(fp)
	if err != nil {
		return nil, fmt.Errorf("failed to find %s file: %w", policyFileName, err)
	}
	if info.IsDir() {
		fp = path.Join(fp, policyFileName)
	}

	fd, err := os.Open(fp)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s file: %w", policyFileName, err)
	}

	return fd, nil
}
