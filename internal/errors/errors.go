package errors

import (
	"fmt"
	"strings"

	"github.com/rs/zerolog"
	snyk_cli_errors "github.com/snyk/error-catalog-golang-public/cli"
)

// OSFlowsExtensionError represents something gone wrong during the
// execution of the CLI Extension. It holds error details, but
// serializes to a human-friendly, customer facing message.
// This is an interim solution until the integration of a generic
// error-catalog interface.
type OSFlowsExtensionError struct {
	err     error
	userMsg string
}

// Error implements error.
func (xerr OSFlowsExtensionError) Error() string {
	return xerr.userMsg
}

// Unwrap implements error.
func (xerr OSFlowsExtensionError) Unwrap() error {
	return xerr.err
}

// ErrorFactory creates errors for the OSTest extension.
type ErrorFactory struct {
	logger *zerolog.Logger
}

// NewErrorFactory creates a new ErrorFactory.
func NewErrorFactory(logger *zerolog.Logger) *ErrorFactory {
	return &ErrorFactory{
		logger: logger,
	}
}

// newErr creates a new OSFlowsExtensionError.
func (ef *ErrorFactory) newErr(err error, userMsg string) *OSFlowsExtensionError {
	ef.logger.Printf("ERROR: %s\n", err)

	return &OSFlowsExtensionError{
		err:     err,
		userMsg: userMsg,
	}
}

// NewEmptyOrgError creates a new error for when no organization ID is found.
func (ef *ErrorFactory) NewEmptyOrgError() *OSFlowsExtensionError {
	return ef.newErr(
		fmt.Errorf("failed to determine org id"),
		"Snyk failed to infer an organization ID. Please make sure to authenticate using `snyk auth`. "+
			"Should the issue persist, explicitly set an organization ID via the `--org` flag.",
	)
}

// NewInvalidOrgIDError creates a new error for when the organization ID is not a valid UUID.
func (ef *ErrorFactory) NewInvalidOrgIDError(orgID string) *OSFlowsExtensionError {
	return ef.newErr(
		fmt.Errorf("invalid organization ID: %s", orgID),
		fmt.Sprintf("The provided organization ID '%s' is not valid. "+
			"Please provide a valid organization ID via the `--org` flag.", orgID),
	)
}

// NewMissingFilenameFlagError creates a new error for when the required file flag is missing.
func (ef *ErrorFactory) NewMissingFilenameFlagError() *OSFlowsExtensionError {
	return ef.newErr(
		fmt.Errorf("file flag not set"),
		"Flag `--file` is required to execute this command. Value should point to a valid manifest file.",
	)
}

// NewNotImplementedError creates a new OSFlowsExtensionError for a not implemented error.
func (ef *ErrorFactory) NewNotImplementedError() *OSFlowsExtensionError {
	// TODO : Remove this error after the transition is complete
	return ef.newErr(
		fmt.Errorf("feature not yet implemented"),
		"This feature is not yet available.",
	)
}

// NewFeatureNotPermittedError creates a new OSFlowsExtensionError for missing feature flags.
func (ef *ErrorFactory) NewFeatureNotPermittedError(featureFlag string) *OSFlowsExtensionError {
	return ef.newErr(
		fmt.Errorf("feature %q not permitted", featureFlag),
		"The feature you are trying to use is not available for your organization.",
	)
}

// NewDirectoryDoesNotExistError creates a new OSFlowsExtensionError for a directory that does not exist.
func (ef *ErrorFactory) NewDirectoryDoesNotExistError(dirPath string) *OSFlowsExtensionError {
	return ef.newErr(
		fmt.Errorf("directory does not exist"),
		fmt.Sprintf("The directory %s does not exist", dirPath),
	)
}

// NewDirectoryIsEmptyError creates a new OSFlowsExtensionError for a directory that is empty.
func (ef *ErrorFactory) NewDirectoryIsEmptyError(dirPath string) *OSFlowsExtensionError {
	return ef.newErr(
		fmt.Errorf("directory is empty"),
		fmt.Sprintf("The directory %s is empty", dirPath),
	)
}

// NewDepGraphWorkflowError creates a new error for failures in the dependency graph workflow.
func (ef *ErrorFactory) NewDepGraphWorkflowError(err error) *OSFlowsExtensionError {
	return ef.newErr(
		fmt.Errorf("error while invoking depgraph workflow: %w", err),
		"An error occurred while running the underlying analysis needed to generate the test.",
	)
}

// NewTestExecutionError creates a new error for failures in the test execution.
func (ef *ErrorFactory) NewTestExecutionError(details string) *OSFlowsExtensionError {
	return ef.newErr(
		fmt.Errorf("test execution failed: %s", details),
		fmt.Sprintf("Test execution failed: %s", details),
	)
}

// NewLegacyJSONTransformerError creates a new error for failures in the
// transformation of snyk schema findings into the legacy json format.
func (ef *ErrorFactory) NewLegacyJSONTransformerError(err error) *OSFlowsExtensionError {
	return ef.newErr(
		fmt.Errorf("legacy json transform: %w", err),
		"An error occurred generating the JSON response.",
	)
}

// NewReachabilityFilterWithoutReachabilityError creates a new error for when
// the --reachability-filter flag is used without the --reachability flag.
func (ef *ErrorFactory) NewReachabilityFilterWithoutReachabilityError() error {
	return snyk_cli_errors.NewInvalidFlagOptionError(
		"The --reachability-filter option requires reachability analysis. Please use it with --reachability=true flag.",
	)
}

// NewSBOMTestWithMultiplePathsError creates a new error for when
// the --sbom flag is used and multie paths are passed to the test command.
func (ef *ErrorFactory) NewSBOMTestWithMultiplePathsError() error {
	return snyk_cli_errors.NewInvalidFlagOptionError(
		"The `--sbom` flag is not supported when providing multiple paths to the `test` command.",
	)
}

// NewInvalidArgCombinationError creates a new error for when
// command line arguments and flags have been combined erroneously.
func (ef *ErrorFactory) NewInvalidArgCombinationError(arg string, flags ...string) error {
	return snyk_cli_errors.NewInvalidFlagOptionError(
		fmt.Sprintf("The argument '%s' cannot be combined with flags %s.", arg, strings.Join(flags, ", ")))
}

// NewInvalidLegacyFlagError creates a new error for when
// new flags are being passed to the legacy CLI.
func (ef *ErrorFactory) NewInvalidLegacyFlagError(flags ...string) error {
	if len(flags) == 0 {
		return snyk_cli_errors.NewInvalidFlagOptionError(
			"An internal error occurred while validating command-line flags.",
		)
	}

	var userMsg string
	if len(flags) > 1 {
		userMsg = fmt.Sprintf("The options %s cannot be used together.", strings.Join(flags, ", "))
	} else {
		userMsg = fmt.Sprintf("The option %s cannot be used in this way.", flags[0])
	}

	return snyk_cli_errors.NewInvalidFlagOptionError(userMsg)
}

// NewUnsupportedFailOnValueError creates a new error for when
// an unsupported value is provided to the --fail-on flag.
func (ef *ErrorFactory) NewUnsupportedFailOnValueError(value string) *OSFlowsExtensionError {
	return ef.newErr(
		fmt.Errorf("unsupported fail-on value: %s", value),
		fmt.Sprintf("Unsupported value '%s' for --fail-on flag. Supported values are: 'all', 'upgradable'.", value),
	)
}
