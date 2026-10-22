package osv

import (
	"regexp"
	"strings"
)

const (
	purlTypeMaven  = "maven"
	purlTypeGolang = "golang"
	purlTypeNpm    = "npm"
	purlTypePypi   = "pypi"
	purlTypeCargo  = "cargo"
	purlTypeNuget  = "nuget"
	purlTypeGem    = "gem"
)

var (
	mavenPreReleasePattern = regexp.MustCompile(`(?i)[.\-](M[0-9]+|RC[0-9]+|alpha[0-9]*|beta[0-9]*|SNAPSHOT)$`)
	pypiNameSeparators     = regexp.MustCompile(`[-_.]+`)
)

func normalizedPurlBase(purl, typ string) string {
	base := purlBase(purl)
	if typ != purlTypePypi {
		return base
	}
	prefix, name, ok := strings.Cut(strings.ToLower(base), "pypi/")
	if !ok {
		return base
	}
	return prefix + "pypi/" + pypiNameSeparators.ReplaceAllString(name, "-")
}

func isMavenPreRelease(version string) bool {
	return mavenPreReleasePattern.MatchString(version)
}

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
