package flags

import "github.com/spf13/pflag"

const (
	FlagRiskScoreThreshold = "risk-score-threshold"
	FlagUnifiedTestAPI     = "unified-test"
)

func GetOSTestFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("snyk-cli-extension-os-flows", pflag.ExitOnError)

	flagSet.Bool(FlagUnifiedTestAPI, false, "Use the unified test API workflow.")
	flagSet.Int(FlagRiskScoreThreshold, -1, "Include findings at or over this risk score threshold")

	return flagSet
}
