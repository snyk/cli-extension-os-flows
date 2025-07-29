package outputworkflow

import (
	"fmt"
	"io"
)

type newLineCloser struct {
	writer io.Writer
}

func (wc *newLineCloser) Write(p []byte) (n int, err error) {
	n, writeErr := wc.writer.Write(p)
	if writeErr != nil {
		return n, fmt.Errorf("failed to write to writer: %w", writeErr)
	}
	return n, nil
}

func (wc *newLineCloser) Close() error {
	// template based renders had an artifact "%" at the end of the content which disappears when adding a newline
	_, err := fmt.Fprintln(wc.writer, "")
	if err != nil {
		return fmt.Errorf("failed to write newline: %w", err)
	}
	return nil
}
