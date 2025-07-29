package outputworkflow

import (
	"fmt"
	"io"
	"os"
)

type delayedFileOpenWriteCloser struct {
	Filename string
	file     io.WriteCloser
}

// Write writes data to the file, opening it lazily if it doesn't exist.
// Close closes the underlying file if it's open.
func (wc *delayedFileOpenWriteCloser) Write(p []byte) (n int, err error) {
	// lazy open file if not exists
	if wc.file == nil {
		pathError := CreateFilePath(wc.Filename)
		if pathError != nil {
			return 0, pathError
		}

		file, fileErr := os.OpenFile(wc.Filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, Fileperm666)
		if fileErr != nil {
			return 0, fmt.Errorf("failed to open file %s: %w", wc.Filename, fileErr)
		}

		wc.file = file
	}

	n, writeErr := wc.file.Write(p)
	if writeErr != nil {
		return n, fmt.Errorf("failed to write to file %s: %w", wc.Filename, writeErr)
	}
	return n, nil
}

func (wc *delayedFileOpenWriteCloser) Close() error {
	if wc.file != nil {
		closeErr := wc.file.Close()
		if closeErr != nil {
			return fmt.Errorf("failed to close file %s: %w", wc.Filename, closeErr)
		}
	}
	return nil
}
