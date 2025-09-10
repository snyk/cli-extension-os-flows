package settings

import (
	"errors"
	"fmt"
)

// Sentinel errors for common conditions.
var (
	ErrEmptyOrgID = errors.New("organization ID cannot be empty")
)

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
