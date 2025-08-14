package fileupload

func chunkChanFiltered[T any](chn <-chan T, size int, filter func(T) bool) <-chan []T {
	out := make(chan []T)
	chunk := make([]T, 0, size)

	go func() {
		defer close(out)

		for el := range chn {
			if filter == nil || filter(el) {
				chunk = append(chunk, el)
			}
			if len(chunk) == size {
				out <- chunk
				chunk = make([]T, 0, size)
			}
		}

		if len(chunk) > 0 {
			out <- chunk
		}
	}()

	return out
}

func chunkChan[T any](chn <-chan T, size int) <-chan []T {
	return chunkChanFiltered(chn, size, nil)
}
