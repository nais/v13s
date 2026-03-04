package collections

import "slices"

func Map[T1, T2 any](s []T1, f func(T1) T2) []T2 {
	r := make([]T2, len(s))
	for i, v := range s {
		r[i] = f(v)
	}
	return r
}

func AnyMatch[T1 any](s []T1, f func(e T1) bool) bool {
	return slices.ContainsFunc(s, f)
}
