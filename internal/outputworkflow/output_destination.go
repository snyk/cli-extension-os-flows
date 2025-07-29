package outputworkflow

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
)

// OutputDestination is an interface for output destinations.
type OutputDestination interface {
	Println(a ...any) (n int, err error)
	Remove(name string) error
	WriteFile(filename string, data []byte, perm fs.FileMode) error
	GetWriter() io.Writer
}

// OutputDestinationImpl is an implementation of the OutputDestination interface.
type OutputDestinationImpl struct{}

// Println prints arguments to the output destination.
func (odi *OutputDestinationImpl) Println(a ...any) (n int, err error) {
	n, err = fmt.Fprintln(os.Stdout, a...)
	if err != nil {
		return n, fmt.Errorf("failed to print to stdout: %w", err)
	}
	return n, nil
}

// Remove removes a file from the output destination.
func (odi *OutputDestinationImpl) Remove(name string) error {
	if _, err := os.Stat(name); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	removeErr := os.Remove(name)
	if removeErr != nil {
		return fmt.Errorf("failed to remove file %s: %w", name, removeErr)
	}
	return nil
}

// WriteFile writes data to a file in the output destination.
func (odi *OutputDestinationImpl) WriteFile(filename string, data []byte, perm fs.FileMode) error {
	writeErr := os.WriteFile(filename, data, perm)
	if writeErr != nil {
		return fmt.Errorf("failed to write file %s: %w", filename, writeErr)
	}
	return nil
}

// GetWriter returns the underlying writer for the output destination.
//
//nolint:ireturn // standard go interface returned for flexibility
func (odi *OutputDestinationImpl) GetWriter() io.Writer {
	return os.Stdout
}

// NewOutputDestination creates a new output destination implementation.
//
//nolint:ireturn // the interface is designed to allow different implementations
func NewOutputDestination() OutputDestination {
	return &OutputDestinationImpl{}
}
