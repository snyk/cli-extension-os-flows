package flags

import "github.com/spf13/pflag"

// FlagFile is the filename of a single manifest file to test.
const FlagFile = "file"

// FlagRiskScoreThreshold is the flag for the minimum risk score for which findings are included.
const FlagRiskScoreThreshold = "risk-score-threshold"

// FlagUnifiedTestAPI forces use of the modern (non-legacy) workflow even without risk score threshold.
const FlagUnifiedTestAPI = "unified-test"

// FlagReachability is used to request the reachability analysis of the source code.
const FlagReachability = "reachability"

// FlagSBOM is used to specify the SBOM file to be tested. TODO: Revisit this after talking with design and product.
const FlagSBOM = "sbom"

// FlagSourceDir is used to specify the source code directory to be tested.
const FlagSourceDir = "source-dir"

// OSTestFlagSet returns a flag set for the Open Source Test workflow.
func OSTestFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("snyk-cli-extension-os-flows", pflag.ExitOnError)

	flagSet.String(FlagFile, "", "Specify a test subject file.")
	flagSet.Bool(FlagUnifiedTestAPI, false, "Use the unified test API workflow.")
	flagSet.Int(FlagRiskScoreThreshold, -1, "Include findings at or over this risk score threshold")

	// Reachability
	flagSet.Bool(FlagReachability, false, "Run reachability analysis on source code.")

	flagSet.String(FlagSBOM, "", "Specify an SBOM file to be tested.")
	flagSet.String(FlagSourceDir, "", "Path of the directory containing the source code.")

	return flagSet
}
