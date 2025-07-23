package bundlestore

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"

	"golang.org/x/net/html/charset"
)

func hash(content []byte) string {
	byteReader := bytes.NewReader(content)
	reader, _ := charset.NewReaderLabel("UTF-8", byteReader) //nolint:errcheck // Code copied verbatim from code-client-go
	utf8content, err := io.ReadAll(reader)
	if err != nil {
		utf8content = content
	}
	b := sha256.Sum256(utf8content)
	sum256 := hex.EncodeToString(b[:])
	return sum256
}

func bundleFileFrom(content []byte) BundleFile {
	file := BundleFile{
		Hash:    hash(content),
		Content: string(content),
	}
	return file
}

func encodeRequestBody(requestBody []byte) (*bytes.Buffer, error) {
	b := new(bytes.Buffer)
	enc := NewEncoder(b)
	_, err := enc.Write(requestBody)
	if err != nil {
		return nil, err
	}
	return b, nil
}
