package osv

import (
	"cmp"
	"strconv"
	"strings"
)

func ApkFixVersion(records []*VulnRecord, storedPurl string) string {
	base := purlBase(storedPurl)
	installed := purlVersion(storedPurl)

	var best string
	for _, rec := range records {
		for _, a := range rec.Affected {
			if a.Package.Purl == "" || !strings.EqualFold(purlBase(a.Package.Purl), base) {
				continue
			}
			for _, r := range a.Ranges {
				for _, e := range r.Events {
					if e.Fixed == "" || compareApkVersions(e.Fixed, installed) <= 0 {
						continue
					}
					if best == "" || compareApkVersions(e.Fixed, best) < 0 {
						best = e.Fixed
					}
				}
			}
		}
	}
	return best
}

func compareApkVersions(a, b string) int {
	aUp, aRel := splitApkRelease(a)
	bUp, bRel := splitApkRelease(b)
	if c := compareSegments(aUp, bUp); c != 0 {
		return c
	}
	return cmp.Compare(aRel, bRel)
}

func splitApkRelease(v string) (string, int) {
	i := strings.LastIndex(v, "-r")
	if i < 0 {
		return v, 0
	}
	rel, err := strconv.Atoi(v[i+2:])
	if err != nil {
		return v, 0
	}
	return v[:i], rel
}

func compareSegments(a, b string) int {
	split := func(r rune) bool { return r == '.' || r == '_' || r == '-' }
	as, bs := strings.FieldsFunc(a, split), strings.FieldsFunc(b, split)
	for i := range min(len(as), len(bs)) {
		an, aErr := strconv.Atoi(as[i])
		bn, bErr := strconv.Atoi(bs[i])
		var c int
		if aErr == nil && bErr == nil {
			c = cmp.Compare(an, bn)
		} else {
			c = strings.Compare(as[i], bs[i])
		}
		if c != 0 {
			return c
		}
	}
	return cmp.Compare(len(as), len(bs))
}
