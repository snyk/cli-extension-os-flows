package reachability

import (
	"errors"
	"fmt"

	"github.com/snyk/error-catalog-golang-public/snyk_errors"
)

// NewWarning creates a warn-level snyk_errors.Error for a reachability failure.
func NewWarning(cause error, options ...snyk_errors.Option) snyk_errors.Error {
	var snykErr snyk_errors.Error
	if errors.As(cause, &snykErr) {
		snykErr.Level = "warn"
		for _, option := range options {
			option(&snykErr)
		}
		return snykErr
	}

	err := snyk_errors.Error{
		Title:  "Reachability analysis failed",
		Detail: fmt.Sprintf("%s. Falling back to testing without reachability information.", cause.Error()),
		Level:  "warn",
	}

	options = append(options, snyk_errors.WithCause(cause))
	for _, option := range options {
		option(&err)
	}

	return err
}

// Sentinel errors for common conditions.
var (
	ErrEmptyOrgID          = errors.New("organization ID cannot be empty")
	ErrEmptyReachabilityID = errors.New("reachability ID cannot be empty")
	ErrScanFailed          = errors.New("reachability scan failed")
	ErrScanStatusUnknown   = errors.New(`reachability scan status is "unknown"`)
	ErrScanTimedOut        = errors.New("reachability scan timed out")
	ErrPollTimedOut        = errors.New("timed out waiting for reachability results")
	ErrPollCancelled       = errors.New("polling context canceled")
)

// UnexpectedScanStatusError is returned when the scan status is not part of the expected enum.
type UnexpectedScanStatusError struct {
	status ScanStatus
}

func (e *UnexpectedScanStatusError) Error() string {
	return fmt.Sprintf("scan status is unexpected: %s", e.status)
}

// NewUnexpectedScanStatusError returnes a new UnexpectedScanStatusError with the specified status.
func NewUnexpectedScanStatusError(status ScanStatus) *UnexpectedScanStatusError {
	return &UnexpectedScanStatusError{status}
}

// HTTPError represents an HTTP error response.
type HTTPError struct {
	StatusCode int
	Status     string
	Operation  string
	Body       []byte
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("unsuccessful request to %s: %s", e.Operation, e.Status)
}

// NewHTTPError creates a new HTTPError with the given parameters.
func NewHTTPError(statusCode int, status, operation string, body []byte) *HTTPError {
	return &HTTPError{
		StatusCode: statusCode,
		Status:     status,
		Operation:  operation,
		Body:       body,
	}
}
