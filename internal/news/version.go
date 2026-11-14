package news

import (
	"cmp"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// inRange tells whether version is in a GitHub vulnerable range, such as
// ">= 5.0.0, < 7.1.0" or "6.4.4". ok is false when either cannot be read:
// the comparison only orders what is shown, it never hides an advisory.
func inRange(version, rng string) (in, ok bool) {
	rng = normalRange(rng)
	if version == "" || strings.TrimSpace(rng) == "" {
		return false, false
	}
	// "< 13.5.7 || >= 14.0.0, < 14.2.10": in any of the alternatives.
	if strings.Contains(rng, "||") {
		readable := false
		for _, alt := range strings.Split(rng, "||") {
			in, ok := inRange(version, alt)
			if ok && in {
				return true, true
			}
			readable = readable || ok
		}
		return false, readable
	}
	// Some advisories leave the comma out: ">=9.5.5 <=14.2.14".
	rng = boundsWithoutComma.ReplaceAllString(strings.TrimSpace(rng), "$1, $2")
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
	rng = normalRange(rng)
	if strings.TrimSpace(rng) == "" {
		return "", false
	}
	parts := strings.Split(branch, ".")
	last, _ := strconv.Atoi(parts[len(parts)-1])
	parts[len(parts)-1] = strconv.Itoa(last + 1)
	lo, hi := branch, strings.Join(parts, ".")
	whole, some := true, true
	if strings.Contains(rng, "||") {
		return "", false // alternatives against a branch: the patch level decides, no mark
	}
	rng = boundsWithoutComma.ReplaceAllString(strings.TrimSpace(rng), "$1, $2")
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

// normalRange writes the signs some advisories type as symbols ("≤ 1.36.0")
// the way the comparison reads them.
func normalRange(rng string) string {
	return strings.NewReplacer("≤", "<=", "≥", ">=", "＜", "<", "＞", ">").Replace(rng)
}

// statusOf compares the version in use with one range of a record. A range
// that names a single release and no fix ("1.30.3", the release a reporter
// tested) proves that release affected, and says nothing of the others: an
// older one is most likely affected too, a newer one may be fixed or not.
func statusOf(version string, a Affected) (string, bool) {
	if a.FixUnknown && singleRelease(a.Versions) {
		if status, ok := versionStatus(version, a.Versions); ok && status != StatusNotAffected {
			return status, true
		}
		return "", false
	}
	return versionStatus(version, a.Versions)
}

// singleRelease tells whether a range names one release, without operator.
func singleRelease(rng string) bool {
	rng = strings.TrimSpace(rng)
	return rng != "" && !strings.ContainsAny(rng, "<>=,|*") && !strings.Contains(rng, " ")
}

// repoStatus compares the version of a product with the range of one of its
// repository advisories. Their maintainers write ranges by hand: "< 4.2.5",
// but also "≤ 1.36.0", "1.35.3" (the last affected release), "all", "3.1.5-4.4.2",
// "<= 4.2.x, all main" or ">= 13.5.1" with the fixes apart. The fixed releases
// listed decide, branch by branch: "4.2.5, 4.1.13" fixes 4.2.6 and 4.1.13, not
// 4.0.2. fixed is the fix of the version's branch, when listed.
//
// Three forms are read branch by branch, the way maintainers mean them:
// several upper bounds ("<= 9.1.2, <= 9.0.6, <= 8.1.4"), one per maintained
// branch; alternatives separated by ";"; and a bare release ("v0.8.3"),
// which proves its own branch only: an older branch may lack the code.
func repoStatus(version, rng, patched string) (status, fixed string, ok bool) {
	if version == "" {
		return "", "", false
	}
	rng = normalRange(strings.TrimSpace(rng))
	patches := releaseList(patched)
	fixed = branchFix(version, patches)
	// Alternatives: hit by any of them.
	if alts := strings.FieldsFunc(rng, func(r rune) bool { return r == ';' }); len(alts) > 1 || strings.Contains(rng, "||") {
		if len(alts) == 1 {
			alts = strings.Split(rng, "||")
		}
		readable := false
		for _, alt := range alts {
			s, f, ok := repoStatus(version, alt, patched)
			if ok && s == StatusAffected {
				return s, cmp.Or(f, fixed), true
			}
			readable = readable || ok
		}
		if readable {
			return StatusNotAffected, fixed, true
		}
		return "", "", false
	}
	if bounds, ok := branchBounds(rng); ok && !isBranch(version) {
		return boundsStatus(version, bounds, patches, fixed)
	}
	// A bare release with its fix: the release a reporter found it in. It
	// proves that release; a later one carrying the fix is not affected; an
	// earlier one may predate the code (LibreChat's "v0.8.3", for a feature
	// 0.8.1 lacks): no verdict, rather than a guess.
	if v := strings.TrimSpace(rng); len(patches) > 0 && versionLike.MatchString(v) && !strings.Contains(v, ".x") && !strings.Contains(v, "*") {
		switch {
		case isBranch(version):
			return "", "", false
		case compareVersions(version, v) == 0:
			return StatusAffected, fixed, true
		case compareVersions(version, v) > 0 && isFixed(version, patches):
			return StatusNotAffected, fixed, true
		case compareVersions(version, v) < 0 && branchOfRelease(strings.TrimPrefix(v, "v")) == branchOfRelease(version):
			return StatusPossiblyAffected, fixed, true // same branch, earlier: whether it has the code decides
		}
		return "", "", false
	}
	expr, readable := repoRange(rng, len(patches) > 0)
	if !readable {
		return "", "", false
	}
	if isBranch(version) {
		if len(patches) > 0 && isFixed(version, patches) {
			return StatusNotAffected, fixed, true // valkey@9 against fixes in 7.2.9, 8.0.3, 8.1.1
		}
		if expr == "" {
			if len(patches) == 0 {
				return "", "", false
			}
			return StatusPossiblyAffected, fixed, true // every release up to a fix: the patch level decides
		}
		status, ok := branchStatus(version, expr)
		if ok && status == StatusAffected && fixed != "" {
			status = StatusPossiblyAffected
		}
		return status, fixed, ok
	}
	in := true
	if expr != "" {
		var ok bool
		if in, ok = inRange(version, expr); !ok {
			return "", "", false
		}
	}
	if in && len(patches) > 0 && isFixed(version, patches) {
		in = false
	}
	if in {
		return StatusAffected, fixed, true
	}
	return StatusNotAffected, fixed, true
}

// branchBounds reads a list of upper bounds only, two or more ("<= 4.2.8,
// <= 4.1.16"): one per branch. ok is false for any other form.
func branchBounds(rng string) ([]string, bool) {
	parts := strings.Split(rng, ",")
	if len(parts) < 2 {
		return nil, false
	}
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !strings.HasPrefix(p, "<") {
			return nil, false
		}
		v := strings.TrimSpace(strings.TrimLeft(p, "<="))
		if !versionLike.MatchString(v) {
			return nil, false
		}
		out = append(out, p)
	}
	return out, len(out) > 1
}

// boundsStatus compares a release with upper bounds given branch by branch:
// the bound of its branch decides; without one, a release below the highest
// bound is on a branch left unfixed, one above every bound is not affected.
func boundsStatus(version string, bounds, patches []string, fixed string) (string, string, bool) {
	highest := ""
	for _, b := range bounds {
		v := strings.TrimPrefix(strings.TrimSpace(strings.TrimLeft(b, "<=")), "v")
		if branchOfRelease(v) == branchOfRelease(version) {
			in, ok := inRange(version, b)
			if !ok {
				return "", "", false
			}
			if !strings.HasPrefix(b, "<=") && fixed == "" {
				fixed = v // "< 4.4.10": the fix of the branch
			}
			if in && !isFixed(version, patches) {
				return StatusAffected, fixed, true
			}
			return StatusNotAffected, fixed, true
		}
		if highest == "" || compareVersions(v, highest) > 0 {
			highest = v
		}
	}
	if compareVersions(version, highest) < 0 && !(len(patches) > 0 && isFixed(version, patches)) {
		return StatusAffected, fixed, true
	}
	return StatusNotAffected, fixed, true
}

// repoRange turns the range of a repository advisory into one inRange reads:
// "" for every release. readable is false for words it cannot place. A bare
// release with fixes listed apart is the last affected one.
func repoRange(rng string, withFixes bool) (string, bool) {
	rng = normalRange(strings.TrimSpace(rng))
	rng = boundsWithoutComma.ReplaceAllString(rng, "$1, $2") // ">=4.6.0-beta.1 <4.6.4"
	// Several bare releases ("v0.8.2-rc2, v0.8.2-rc3") list the affected ones.
	if parts := strings.Split(rng, ","); len(parts) > 1 && !strings.ContainsAny(rng, "<>=*") {
		var list []string
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if !versionLike.MatchString(p) || strings.Contains(p, ".x") {
				list = nil
				break
			}
			list = append(list, "= "+p)
		}
		if list != nil {
			return strings.Join(list, " || "), true
		}
	}
	var out []string
	for _, part := range strings.Split(rng, ",") {
		part = strings.TrimSpace(part)
		low := strings.ToLower(part)
		switch {
		case part == "", low == "all", low == "*", low == "all versions", low == "main", low == "all main", strings.HasPrefix(low, "all "):
			continue
		case hyphenRange.MatchString(part):
			m := hyphenRange.FindStringSubmatch(part)
			out = append(out, ">= "+m[1], "<= "+m[2])
			continue
		}
		op := part[:len(part)-len(strings.TrimLeft(part, "<>="))]
		v := strings.TrimSpace(part[len(op):])
		if v == "" || !versionLike.MatchString(v) {
			return "", false
		}
		// "<= 4.2.x": every 4.2 release.
		if base, ok := strings.CutSuffix(strings.TrimSuffix(v, ".*"), ".x"); ok || strings.HasSuffix(v, ".*") {
			if !ok {
				base = strings.TrimSuffix(v, ".*")
			}
			switch op {
			case "<=", "":
				out = append(out, "< "+nextBranch(base))
				if op == "" {
					out = append(out, ">= "+base)
				}
			case "<":
				out = append(out, "< "+base)
			default:
				out = append(out, op+" "+base)
			}
			continue
		}
		if op == "" {
			if withFixes {
				op = "<="
			} else {
				op = "="
			}
		}
		out = append(out, op+" "+v)
	}
	return strings.Join(out, ", "), true
}

var (
	hyphenRange = regexp.MustCompile(`^v?(\d+(?:\.\d+)+)\s*-\s*v?(\d+(?:\.\d+)+)$`)
	versionLike = regexp.MustCompile(`^v?\d+(\.[0-9A-Za-z*]+)*([-+][0-9A-Za-z.\-]+)?$`)
)

// nextBranch gives the branch after one: 4.2 → 4.3.
func nextBranch(base string) string {
	parts := strings.Split(strings.TrimPrefix(base, "v"), ".")
	n, err := strconv.Atoi(parts[len(parts)-1])
	if err != nil {
		return base
	}
	parts[len(parts)-1] = strconv.Itoa(n + 1)
	return strings.Join(parts, ".")
}

// releaseList reads a list of releases: "4.2.5, 4.1.13", ">= 2.46.0", "1.35.4".
func releaseList(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '|' }) {
		f = strings.TrimLeft(f, "<>=v")
		if f != "" && versionLike.MatchString(f) {
			out = append(out, f)
		}
	}
	return out
}

// branchOfRelease gives the major and minor of a release: 4.2 for 4.2.5.
func branchOfRelease(v string) string {
	parts := strings.SplitN(strings.TrimPrefix(v, "v"), ".", 3)
	if len(parts) < 2 {
		return parts[0]
	}
	return parts[0] + "." + parts[1]
}

// isFixed tells whether a release is fixed by one of the releases listed: a
// fix on its own branch at or below it, or every fix below it (a later branch).
func isFixed(version string, patches []string) bool {
	highest := ""
	for _, p := range patches {
		if branchOfRelease(p) == branchOfRelease(version) && compareVersions(version, p) >= 0 {
			return true
		}
		if highest == "" || compareVersions(p, highest) > 0 {
			highest = p
		}
	}
	return highest != "" && compareVersions(version, highest) >= 0
}

// branchFix gives the fix listed for the branch of a version, or the lowest
// one above it.
func branchFix(version string, patches []string) string {
	var best string
	for _, p := range patches {
		if branchOfRelease(p) == branchOfRelease(version) {
			return p
		}
		if compareVersions(p, version) > 0 && (best == "" || compareVersions(p, best) < 0) {
			best = p
		}
	}
	return best
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

// boundsWithoutComma finds two bounds written side by side without a comma.
var boundsWithoutComma = regexp.MustCompile(`([0-9A-Za-z.\-+]) +([<>=])`)

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
