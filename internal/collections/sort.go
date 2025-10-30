package collections

import "sort"

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
