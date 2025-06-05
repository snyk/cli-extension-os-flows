package errors

import (
	"fmt"

	"github.com/rs/zerolog"
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
