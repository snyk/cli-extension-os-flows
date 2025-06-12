package bundlestore

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"path/filepath"

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

func toRelativeUnixPath(baseDir, absoluteFilePath string) (string, error) {
	relativePath, err := filepath.Rel(baseDir, absoluteFilePath)
	if err != nil {
		relativePath = absoluteFilePath
		if baseDir != "" {
			errMsg := fmt.Sprint("could not get relative path for file: ", absoluteFilePath, " and root path: ", baseDir)
			return "", fmt.Errorf("%s: %w", errMsg, err)
		}
	}

	relativePath = filepath.ToSlash(relativePath) // treat all paths as unix paths
	return relativePath, nil
}
