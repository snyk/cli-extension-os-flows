package validation

import (
	"os"
	"strconv"
	"strings"

	snyk_cli_errors "github.com/snyk/error-catalog-golang-public/cli"
	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/cli-extension-os-flows/internal/outputworkflow"
	"github.com/snyk/cli-extension-os-flows/pkg/flags"
)

// Command is the type for workflow command names passed to ValidateFlagValues.
type Command string

// CommandTest is the command name for the test workflow.
const CommandTest Command = "test"

// CommandMonitor is the command name for the monitor workflow.
const CommandMonitor Command = "monitor"

// isEmptyFlagValue reports whether the value of a flag should be treated as
// "not provided". It returns true for both the empty string (from --flag=) and
// flags.InvalidFlagValue (from a bare --flag with no =, where pflag uses NoOptDefVal).
// Use this for flags where both forms are always invalid (e.g. --exclude, --json-file-output).
// For flags where --flag= is intentionally valid (e.g. --project-tags=), compare
// directly against flags.InvalidFlagValue instead.
func isEmptyFlagValue(v string) bool {
	return v == "" || v == flags.InvalidFlagValue
}

// ValidateFlagValues applies legacy-compat business rules for test and monitor flag values.
// command is the workflow command name; only CommandTest allows --json-file-output and --sarif-file-output.
// It returns an error if any rule is violated.
func ValidateFlagValues(cfg configuration.Configuration, command Command) error {
	if err := validateOutputFileFlagsOnlyForTest(cfg, command); err != nil {
		return err
	}
	if err := validateExclude(cfg); err != nil {
		return err
	}
	if err := validateFileNonEmptyWhenSet(cfg); err != nil {
		return err
	}
	if err := validateFileAndProjectName(cfg); err != nil {
		return err
	}
	if err := validateDetectionDepth(cfg); err != nil {
		return err
	}
	if err := validateJSONFileOutput(cfg); err != nil {
		return err
	}
	if err := validateSarifFileOutput(cfg); err != nil {
		return err
	}
	if err := validateProjectBusinessCriticality(cfg); err != nil {
		return err
	}
	//nolint:revive // Code is cleaner this way.
	if err := validateProjectTags(cfg); err != nil {
		return err
	}
	return nil
}

// validateOutputFileFlagsOnlyForTest returns an error if command is not CommandTest and json-file-output or sarif-file-output is set.
func validateOutputFileFlagsOnlyForTest(cfg configuration.Configuration, command Command) error {
	if command == CommandTest {
		return nil
	}
	if cfg.IsSet(outputworkflow.OutputConfigKeyJSONFile) {
		return snyk_cli_errors.NewInvalidFlagOptionError(
			"The following option combination is not currently supported: " + string(command) + " + json-file-output",
		)
	}
	if cfg.IsSet(outputworkflow.OutputConfigKeySarifFileOutput) {
		return snyk_cli_errors.NewInvalidFlagOptionError(
			"The following option combination is not currently supported: " + string(command) + " + sarif-file-output",
		)
	}
	return nil
}

func validateExclude(cfg configuration.Configuration) error {
	if !cfg.IsSet(flags.FlagExclude) {
		return nil
	}
	if !cfg.IsSet(flags.FlagAllProjects) && !cfg.IsSet(flags.FlagYarnWorkspaces) {
		return snyk_cli_errors.NewInvalidFlagOptionError("The --exclude option can only be used in combination with --all-projects or --yarn-workspaces.")
	}
	excludeValue := cfg.GetString(flags.FlagExclude)
	if isEmptyFlagValue(excludeValue) {
		return snyk_cli_errors.NewEmptyFlagOptionError("Empty --exclude argument. Did you mean --exclude=subdirectory ?")
	}
	if strings.ContainsRune(excludeValue, os.PathSeparator) {
		return snyk_cli_errors.NewInvalidFlagOptionError(
			"The --exclude argument must be a comma separated list of directory or file names and cannot contain a path.",
		)
	}
	return nil
}

func validateFileNonEmptyWhenSet(cfg configuration.Configuration) error {
	if !cfg.IsSet(flags.FlagFile) {
		return nil
	}
	if cfg.GetString(flags.FlagFile) == "" {
		return snyk_cli_errors.NewEmptyFlagOptionError("Empty --file argument. Did you mean --file=path/to/file ?")
	}
	return nil
}

func validateFileAndProjectName(cfg configuration.Configuration) error {
	fileValue := cfg.GetString(flags.FlagFile)
	if !strings.HasSuffix(fileValue, ".sln") {
		return nil
	}
	if !cfg.IsSet(flags.FlagProjectName) {
		return nil
	}
	return snyk_cli_errors.NewInvalidFlagOptionError("The following option combination is not currently supported: file=*.sln + project-name")
}

func validateDetectionDepth(cfg configuration.Configuration) error {
	if !cfg.IsSet(flags.FlagDetectionDepth) {
		return nil
	}
	s := cfg.GetString(flags.FlagDetectionDepth)
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return snyk_cli_errors.NewInvalidFlagOptionError("Unsupported value for --detection-depth flag. Expected a positive integer.")
	}
	return nil
}

func validateJSONFileOutput(cfg configuration.Configuration) error {
	if !cfg.IsSet(outputworkflow.OutputConfigKeyJSONFile) {
		return nil
	}
	if isEmptyFlagValue(cfg.GetString(outputworkflow.OutputConfigKeyJSONFile)) {
		return snyk_cli_errors.NewEmptyFlagOptionError("Empty --json-file-output argument. Did you mean --file=path/to/output-file.json ?")
	}
	return nil
}

func validateSarifFileOutput(cfg configuration.Configuration) error {
	if !cfg.IsSet(outputworkflow.OutputConfigKeySarifFileOutput) {
		return nil
	}
	if isEmptyFlagValue(cfg.GetString(outputworkflow.OutputConfigKeySarifFileOutput)) {
		return snyk_cli_errors.NewEmptyFlagOptionError("Empty --sarif-file-output argument. Did you mean --file=path/to/output-file.json ?")
	}
	return nil
}

func validateProjectBusinessCriticality(cfg configuration.Configuration) error {
	if !cfg.IsSet(flags.FlagProjectBusinessCriticality) {
		return nil
	}
	// An empty value (--project-business-criticality=) is intentional: it clears existing values.
	// Only a bare flag with no = (signaled by InvalidFlagValue) is an error, because the user
	// likely forgot the = and would accidentally clear their existing project attributes.
	if cfg.GetString(flags.FlagProjectBusinessCriticality) == flags.InvalidFlagValue {
		return snyk_cli_errors.NewEmptyFlagOptionError(
			"--project-business-criticality must contain an '=' with a comma-separated list of values." +
				" To clear all existing values, pass no values i.e. --project-business-criticality=",
		)
	}
	return nil
}

func validateProjectTags(cfg configuration.Configuration) error {
	if !cfg.IsSet(flags.FlagProjectTags) {
		return nil
	}
	// An empty value (--project-tags=) is intentional: it clears existing tags.
	// Only a bare flag with no = (signaled by InvalidFlagValue) is an error, because the user
	// likely forgot the = and would accidentally clear their existing tags.
	if cfg.GetString(flags.FlagProjectTags) == flags.InvalidFlagValue {
		return snyk_cli_errors.NewEmptyFlagOptionError(
			"--project-tags must contain an '=' with a comma-separated list of pairs (also separated with an '=')." +
				" To clear all existing values, pass no values i.e. --project-tags=",
		)
	}
	return nil
}
