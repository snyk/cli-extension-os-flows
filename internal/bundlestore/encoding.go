package bundlestore

import (
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
)

// EncoderWriter is a writer that base64 encodes, compresses, and writes data to an underlying writer.
type EncoderWriter struct {
	w io.Writer
}

// NewEncoder returns a new EncoderWriter.
// Writes to the returned writer are compressed, base64 encoded and written to w.
func NewEncoder(w io.Writer) *EncoderWriter {
	enc := new(EncoderWriter)
	enc.w = w
	return enc
}

func (ew *EncoderWriter) Write(b []byte) (int, error) {
	zipWriter := gzip.NewWriter(ew.w)
	b64Writer := base64.NewEncoder(base64.StdEncoding, zipWriter)

	n, err := b64Writer.Write(b)
	if err != nil {
		return n, fmt.Errorf("failed to write to base64 encoder: %w", err)
	}

	if err = b64Writer.Close(); err != nil {
		return n, fmt.Errorf("failed to close base64 encoder: %w", err)
	}
	if err = zipWriter.Close(); err != nil {
		return n, fmt.Errorf("failed to close gzip writer: %w", err)
	}

	return n, nil
}
