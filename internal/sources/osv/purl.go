package osv

import (
	"regexp"
	"strings"

	"github.com/package-url/packageurl-go"
	"golang.org/x/mod/module"
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

var osvEcosystems = map[string]string{
	purlTypeMaven:  "Maven",
	purlTypeGolang: "Go",
	purlTypeNpm:    "npm",
	purlTypePypi:   "PyPI",
	purlTypeCargo:  "crates.io",
	purlTypeNuget:  "NuGet",
	purlTypeGem:    "RubyGems",
}

var (
	mavenRuntimeClassifier = regexp.MustCompile(`(?i)[.\-](jre|jdk|android)\d*$`)
	numericRelease         = regexp.MustCompile(`^v?\d+(?:\.\d+)*`)
	pep440Version          = regexp.MustCompile(`(?i)^v?(?:\d+!)?\d+(?:\.\d+)*([-_.]?(?:a|b|c|rc|alpha|beta|pre|preview)[-_.]?\d*)?(?:-\d+|[-_.]?(?:post|rev|r)[-_.]?\d*)?([-_.]?dev[-_.]?\d*)?(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?$`)
	pypiNameSeparators     = regexp.MustCompile(`[-_.]+`)
)

type purl struct {
	typ       string
	namespace string
	name      string
	version   string
}

func parsePurl(raw string) (purl, bool) {
	p, err := packageurl.FromString(raw)
	if err != nil {
		return purl{}, false
	}
	typ := strings.ToLower(p.Type)
	name := p.Name
	if typ == purlTypePypi {
		name = pypiNameSeparators.ReplaceAllString(strings.ToLower(name), "-")
	}
	return purl{typ: typ, namespace: p.Namespace, name: name, version: p.Version}, true
}

func (p purl) samePackage(o purl) bool {
	return p.typ == o.typ && strings.EqualFold(p.namespace, o.namespace) && strings.EqualFold(p.name, o.name)
}

// withoutRuntimeClassifier drops Maven runtime classifiers (.jre11, -android) so they do not affect ordering.
func withoutRuntimeClassifier(typ, raw string) string {
	if typ != purlTypeMaven {
		return raw
	}
	return mavenRuntimeClassifier.ReplaceAllString(raw, "")
}

// isPreReleaseFix reports whether a version sorts below its own numeric release (2.0.0-rc1 < 2.0.0), so .Final, .v20201120 and post-releases stay stable.
func isPreReleaseFix(typ, raw string) bool {
	switch typ {
	case purlTypePypi:
		return isPyPIPreRelease(raw)
	case purlTypeGolang:
		if module.IsPseudoVersion(goVersion(raw)) {
			return false
		}
	}
	release := numericRelease.FindString(raw)
	if release == "" || release == raw {
		return false
	}
	v, ok := parseVersion(typ, raw)
	r, releaseOk := parseVersion(typ, release)
	return ok && releaseOk && v.LT(r)
}

// isPyPIPreRelease follows PEP 440: a pre-release segment (a, b, rc, ...) or a dev segment marks a pre-release, epochs and post-releases included.
func isPyPIPreRelease(raw string) bool {
	m := pep440Version.FindStringSubmatch(raw)
	return m != nil && (m[1] != "" || m[2] != "")
}

func goVersion(raw string) string {
	if strings.HasPrefix(raw, "v") {
		return raw
	}
	return "v" + raw
}
