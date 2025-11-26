package collections

import "sort"

func Filter[T any](s []T, f func(T) bool) []T {
	var r []T
	for _, v := range s {
		if f(v) {
			r = append(r, v)
		}
	}
	return r
}

func Map[T1, T2 any](s []T1, f func(T1) T2) []T2 {
	r := make([]T2, len(s))
	for i, v := range s {
		r[i] = f(v)
	}
	return r
}

func AnyMatch[T1 any](s []T1, f func(e T1) bool) bool {
	for _, v := range s {
		if f(v) {
			return true
		}
	}
	return false
}

func SortByFields[T any](items []T, getters ...func(T) string) {
	sort.SliceStable(items, func(i, j int) bool {
		for _, get := range getters {
			a, b := get(items[i]), get(items[j])
			if a < b {
				return true
			}
			if a > b {
				return false
			}
		}
		return false
	})
}

func ChunkImages[T any](items []T, size int) [][]T {
	if size <= 0 {
		panic("chunk size must be > 0")
	}

	var chunks [][]T
	for size < len(items) {
		items, chunks = items[size:], append(chunks, items[0:size:size])
	}
	chunks = append(chunks, items)
	return chunks
}
