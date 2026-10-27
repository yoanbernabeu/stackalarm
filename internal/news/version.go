package news

import (
	"cmp"
	"strconv"
	"strings"
	"unicode"
)

// inRange tells whether version is in a GitHub vulnerable range, such as
// ">= 5.0.0, < 7.1.0" or "6.4.4". ok is false when either cannot be read:
// the comparison only orders what is shown, it never hides an advisory.
func inRange(version, rng string) (in, ok bool) {
	if version == "" || strings.TrimSpace(rng) == "" {
		return false, false
	}
	for _, c := range strings.Split(rng, ",") {
		c = strings.TrimSpace(c)
		op := c[:len(c)-len(strings.TrimLeft(c, "<>="))]
		v := strings.TrimSpace(c[len(op):])
		if v == "" {
			return false, false
		}
		d := compareVersions(version, v)
		switch op {
		case "", "=":
			in = d == 0
		case "<":
			in = d < 0
		case "<=":
			in = d <= 0
		case ">":
			in = d > 0
		case ">=":
			in = d >= 0
		default:
			return false, false
		}
		if !in {
			return false, true
		}
	}
	return true, true
}

// compareVersions compares dotted versions part by part, numbers as numbers:
// 1.10.0 > 1.9.0, 1.0.0 > 1.0.0-rc.1. Good enough for ordering.
func compareVersions(a, b string) int {
	a, b = strings.TrimPrefix(a, "v"), strings.TrimPrefix(b, "v")
	ar, apre, _ := strings.Cut(a, "-")
	br, bpre, _ := strings.Cut(b, "-")
	as, bs := versionParts(ar), versionParts(br)
	for i := range max(len(as), len(bs)) {
		x, y := "0", "0"
		if i < len(as) {
			x = as[i]
		}
		if i < len(bs) {
			y = bs[i]
		}
		if c := comparePart(x, y); c != 0 {
			return c
		}
	}
	switch { // a pre-release comes before its release
	case apre == bpre:
		return 0
	case apre == "":
		return 1
	case bpre == "":
		return -1
	}
	return cmp.Compare(apre, bpre)
}

func versionParts(v string) []string {
	return strings.FieldsFunc(v, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })
}

func comparePart(x, y string) int {
	nx, ex := strconv.Atoi(x)
	ny, ey := strconv.Atoi(y)
	if ex == nil && ey == nil {
		return cmp.Compare(nx, ny)
	}
	return cmp.Compare(x, y)
}
