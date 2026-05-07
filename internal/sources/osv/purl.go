package osv

import "strings"

func purlType(purl string) string {
	s := strings.ToLower(purl)
	s = strings.TrimPrefix(s, "pkg:")
	if before, _, ok := strings.Cut(s, "/"); ok {
		return before
	}
	return s
}

func purlBase(purl string) string {
	if i := strings.IndexByte(purl, '?'); i >= 0 {
		purl = purl[:i]
	}
	if i := strings.IndexByte(purl, '#'); i >= 0 {
		purl = purl[:i]
	}
	if i := strings.IndexByte(purl, '@'); i >= 0 {
		purl = purl[:i]
	}
	return purl
}

func purlVersion(purl string) string {
	if i := strings.IndexByte(purl, '?'); i >= 0 {
		purl = purl[:i]
	}
	if i := strings.IndexByte(purl, '#'); i >= 0 {
		purl = purl[:i]
	}
	if _, after, ok := strings.Cut(purl, "@"); ok {
		return after
	}
	return ""
}
