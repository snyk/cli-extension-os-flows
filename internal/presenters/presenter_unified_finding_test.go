package presenters_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/cli-extension-os-flows/internal/presenters"
)

func TestJsonWriter(t *testing.T) {
	t.Run("strip whitespaces while writing", func(t *testing.T) {
		buffer := &bytes.Buffer{}
		writerUnderTest := presenters.NewJsonWriter(buffer, true)

		input := []byte(`{
	"name": "myName",
	"address": "myAddr"
}`)

		expected := `{"name": "myName","address": "myAddr"}`

		bytesWritten, err := writerUnderTest.Write(input)
		assert.NoError(t, err)
		assert.Equal(t, len(input), bytesWritten)
		assert.Equal(t, expected, buffer.String())
	})

	t.Run("Don't strip whitespaces while writing", func(t *testing.T) {
		buffer := &bytes.Buffer{}
		writerUnderTest := presenters.NewJsonWriter(buffer, false)

		input := []byte(`{
	"name": "myName",
    "address": "myAddr"
}`)

		bytesWritten, err := writerUnderTest.Write(input)
		assert.NoError(t, err)
		assert.Equal(t, len(input), bytesWritten)
		assert.Equal(t, input, buffer.Bytes())
	})
}
