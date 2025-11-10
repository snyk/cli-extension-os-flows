package transform_test

import (
	"encoding/json"
	"os"
	"slices"
	"testing"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/legacy/definitions"
)

func loadFindings(t *testing.T, path string) []testapi.FindingData {
	t.Helper()
	buf, err := os.ReadFile(path)
	require.NoError(t, err)

	var response FindingsResponse
	err = json.Unmarshal(buf, &response)
	require.NoError(t, err)

	return response.Data
}

type FindingsResponse struct {
	Data []testapi.FindingData `json:"data"`
}

//nolint:unparam // vulnID is always the same in tests but keeping parameter for clarity
func findByID(vulnID string, vulns []definitions.Vulnerability) definitions.Vulnerability {
	index := slices.IndexFunc(vulns, func(vuln definitions.Vulnerability) bool {
		return vuln.Id == vulnID
	})
	return vulns[index]
}
