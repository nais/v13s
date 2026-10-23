package osv

import (
	"regexp"
	"strings"

	"deps.dev/util/semver"
	"github.com/package-url/packageurl-go"
)

const (
	purlTypeMaven  = "maven"
	purlTypeGolang = "golang"
	purlTypeNpm    = "npm"
	purlTypePypi   = "pypi"
	purlTypeCargo  = "cargo"
	purlTypeNuget  = "nuget"
	purlTypeGem    = "gem"
	purlTypeDeb    = "deb"
	purlTypeApk    = "apk"
	purlTypeRpm    = "rpm"
)

type ecosystem struct {
	osvName string
	system  semver.System
}

var ecosystems = map[string]ecosystem{
	purlTypeMaven:  {"Maven", semver.Maven},
	purlTypeGolang: {"Go", semver.Go},
	purlTypeNpm:    {"npm", semver.NPM},
	purlTypePypi:   {"PyPI", semver.PyPI},
	purlTypeCargo:  {"crates.io", semver.Cargo},
	purlTypeNuget:  {"NuGet", semver.NuGet},
	purlTypeGem:    {"RubyGems", semver.RubyGems},
	purlTypeDeb:    {"Debian", semver.DefaultSystem},
	purlTypeApk:    {"Alpine", semver.DefaultSystem},
	purlTypeRpm:    {"Red Hat", semver.DefaultSystem},
}

var (
	mavenRuntimeClassifier = regexp.MustCompile(`(?i)[.\-](jre|jdk|android)\d*$`)
	pypiDevRelease         = regexp.MustCompile(`(?i)\d[._\-]?dev[._\-]?\d*(?:\+.*)?$`)
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

// canonicalVersion drops Maven runtime classifiers (.jre11, -android) and adds Go's v prefix before versions are parsed.
func canonicalVersion(typ, raw string) string {
	switch {
	case typ == purlTypeMaven:
		return mavenRuntimeClassifier.ReplaceAllString(raw, "")
	case typ == purlTypeGolang && !strings.HasPrefix(raw, "v"):
		return "v" + raw
	default:
		return raw
	}
}

func isPreReleaseFix(typ, raw string) bool {
	eco, known := ecosystems[typ]
	if !known || eco.system == semver.DefaultSystem {
		return false
	}
	if typ == purlTypePypi && pypiDevRelease.MatchString(raw) {
		return true
	}
	v, err := eco.system.Parse(canonicalVersion(typ, raw))
	return err == nil && v.IsPrerelease()
}
