package util

// MapWithErr maps a slice of items to a slice of items, applying a mapper function to each item.
// If the mapper function returns an error, the error is returned immediately.
func MapWithErr[TIn, TOut any](input []TIn, mapper func(TIn) (TOut, error)) ([]TOut, error) {
	output := make([]TOut, len(input))
	for i, item := range input {
		out, err := mapper(item)
		if err != nil {
			return nil, err
		}
		output[i] = out
	}
	return output, nil
}
