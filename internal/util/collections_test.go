package util_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/util"
)

func TestMapWithErr_Success(t *testing.T) {
	input := []int{1, 2, 3, 4, 5}
	mapper := func(i int) (string, error) {
		return string(rune('0' + i)), nil
	}

	result, err := util.MapWithErr(input, mapper)

	require.NoError(t, err)
	assert.Equal(t, []string{"1", "2", "3", "4", "5"}, result)
}

func TestMapWithErr_Error(t *testing.T) {
	input := []int{1, 2, 3}
	mapper := func(i int) (string, error) {
		if i == 2 {
			return "", errors.New("whoops")
		}
		return "", nil
	}

	result, err := util.MapWithErr(input, mapper)

	require.Error(t, err)
	assert.ErrorContains(t, err, "whoops")
	assert.Nil(t, result)
}
