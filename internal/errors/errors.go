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

func (xerr OSFlowsExtensionError) Error() string {
	return xerr.userMsg
}

func (xerr OSFlowsExtensionError) Unwrap() error {
	return xerr.err
}

type ErrorFactory struct {
	logger *zerolog.Logger
}

func NewErrorFactory(logger *zerolog.Logger) *ErrorFactory {
	return &ErrorFactory{
		logger: logger,
	}
}

func (ef *ErrorFactory) newErr(err error, userMsg string) *OSFlowsExtensionError {
	ef.logger.Printf("ERROR: %s\n", err)

	return &OSFlowsExtensionError{
		err:     err,
		userMsg: userMsg,
	}
}

func (ef *ErrorFactory) NewNotImplementedError() *OSFlowsExtensionError {
	// TODO : Remove this error after the transition is complete
	return ef.newErr(
		fmt.Errorf("unified test flow not yet implemented"),
		"unified test flow not yet implemented. Please try again later.",
	)
}
