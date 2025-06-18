// Package ostest implements the "test" command for the Snyk CLI's Open Source security testing.
package ostest

import (
	"encoding/json"
	"fmt"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
)

// processTestResult logs the details from the TestResult interface.
//
//nolint:forbidigo // todo: for demo purposes
func processTestResult(status testapi.TestResult) {
	fmt.Println("--- Test Result Details ---")
	if status.GetTestID() != nil {
		fmt.Printf("Test ID: %s\n", status.GetTestID().String())
	} else {
		fmt.Printf("Test ID: <nil>\n")
	}
	fmt.Printf("State:   %s\n", status.GetExecutionState())
	if status.GetPassFail() != nil {
		fmt.Printf("Outcome: %s\n", *status.GetPassFail())
	} else {
		fmt.Printf("Outcome: <nil>\n")
	}
	if status.GetOutcomeReason() != nil {
		fmt.Printf("Reason:  %s\n", *status.GetOutcomeReason())
	}
	logJSON("Effective Summary:", status.GetEffectiveSummary())
	fmt.Println("-------------------------")
}

// logJSON is a helper function to log JSON data with a prefix.
//
//nolint:forbidigo // todo: for demo purposes
func logJSON(prefix string, v any) {
	if v == nil {
		fmt.Printf("%s <nil>\n", prefix)
		return
	}

	jsonBytes, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Printf("%s Error marshaling to JSON: %v\n", prefix, err)
		return
	}

	fmt.Printf("%s\n%s\n", prefix, string(jsonBytes))
}
