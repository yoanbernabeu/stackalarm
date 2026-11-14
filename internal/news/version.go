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

// versionStatus compares a version in use with a vulnerable range, and tells
// StatusAffected, StatusPossiblyAffected or StatusNotAffected; ok is false when
// either cannot be read. A branch (node@20, php@8.3: fewer than three parts)
// is affected when the whole branch is in the range, so no release of it is
// fixed, and possibly affected when only some of its releases are: its patch
// level decides.
func versionStatus(version, rng string) (status string, ok bool) {
	if isBranch(version) {
		return branchStatus(version, rng)
	}
	in, ok := inRange(version, rng)
	if !ok {
		return "", false
	}
	if in {
		return StatusAffected, true
	}
	return StatusNotAffected, true
}

// isBranch tells whether a version names a branch rather than a release:
// one or two numeric parts ("20", "8.3").
func isBranch(version string) bool {
	parts := strings.Split(strings.TrimPrefix(version, "v"), ".")
	if len(parts) > 2 {
		return false
	}
	for _, p := range parts {
		if _, err := strconv.Atoi(p); err != nil {
			return false
		}
	}
	return true
}

// branchStatus compares every release of a branch with a range: from the
// branch itself (8.3, read as 8.3.0) to the next one (8.4) excluded.
func branchStatus(branch, rng string) (string, bool) {
	branch = strings.TrimPrefix(branch, "v")
	if strings.TrimSpace(rng) == "" {
		return "", false
	}
	parts := strings.Split(branch, ".")
	last, _ := strconv.Atoi(parts[len(parts)-1])
	parts[len(parts)-1] = strconv.Itoa(last + 1)
	lo, hi := branch, strings.Join(parts, ".")
	whole, some := true, true
	for _, c := range strings.Split(rng, ",") {
		c = strings.TrimSpace(c)
		op := c[:len(c)-len(strings.TrimLeft(c, "<>="))]
		v := strings.TrimSpace(c[len(op):])
		if v == "" {
			return "", false
		}
		switch op {
		case ">=":
			whole, some = whole && compareVersions(lo, v) >= 0, some && compareVersions(v, hi) < 0
		case ">":
			whole, some = whole && compareVersions(lo, v) > 0, some && compareVersions(v, hi) < 0
		case "<":
			whole, some = whole && compareVersions(v, hi) >= 0, some && compareVersions(v, lo) > 0
		case "<=":
			whole, some = whole && compareVersions(v, hi) >= 0, some && compareVersions(v, lo) >= 0
		case "", "=":
			whole, some = false, some && (v == branch || strings.HasPrefix(v, branch+"."))
		default:
			return "", false
		}
	}
	switch {
	case whole && some:
		return StatusAffected, true
	case some:
		return StatusPossiblyAffected, true
	}
	return StatusNotAffected, true
}

// tidyRange repairs the ranges some records write wrongly: a wildcard bound
// (">= 8.3.*" is ">= 8.3"), and a lower bound that excludes every version
// below the upper one (">= 1.3.2, < 1.3.2", a frequent slip of the NVD for
// "< 1.3.2"): read literally, such a range holds nothing and hides the flaw.
func tidyRange(rng string) string {
	var lower, upper []string
	for _, c := range strings.Split(rng, ",") {
		c = strings.TrimSpace(c)
		c = strings.TrimSuffix(strings.TrimSuffix(c, ".*"), ".x")
		switch {
		case c == "":
		case c == ">= 0", c == ">=0", c == ">= 0.0.0": // every version: no bound
		case strings.HasPrefix(c, ">"):
			lower = append(lower, c)
		default:
			upper = append(upper, c)
		}
	}
	if len(lower) == 1 && len(upper) == 1 && strings.HasPrefix(upper[0], "<") {
		lo := strings.TrimSpace(strings.TrimLeft(lower[0], ">="))
		up := strings.TrimSpace(strings.TrimLeft(upper[0], "<="))
		if d := compareVersions(lo, up); d > 0 || d == 0 && !(strings.HasPrefix(lower[0], ">=") && strings.HasPrefix(upper[0], "<=")) {
			lower = nil
		}
	}
	return strings.Join(append(lower, upper...), ", ")
}

// fixedIn reads the first fixed version of a range whose upper bound excludes
// it ("< 15.2.3"), or "" when the range gives none.
func fixedIn(rng string) string {
	for _, c := range strings.Split(rng, ",") {
		c = strings.TrimSpace(c)
		if v, ok := strings.CutPrefix(c, "<"); ok && !strings.HasPrefix(v, "=") {
			return strings.TrimSpace(v)
		}
	}
	return ""
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
