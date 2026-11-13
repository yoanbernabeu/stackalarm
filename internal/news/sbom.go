package news

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	neturl "net/url"
	"regexp"
	"slices"
	"strings"
)

// Component is a package an SBOM lists, with the OSV ecosystem its package
// URL names. For a distribution package, Name and Version are those of the
// source package: the security trackers of the distributions know no other.
type Component struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
}

// SBOM is what a software bill of materials gives to look up.
type SBOM struct {
	Components []Component
	// Skipped counts the components that cannot be looked up, by reason: a
	// gap in the watch is always reported.
	Skipped map[string]int
}

// purlEcosystems maps a package URL type to its OSV ecosystem, for the
// ecosystems whose name does not depend on a distribution.
var purlEcosystems = map[string]string{
	"npm": "npm", "composer": "Packagist", "pypi": "PyPI", "golang": "Go", "gem": "RubyGems", "cargo": "crates.io",
	"maven": "Maven", "nuget": "NuGet", "pub": "Pub", "hex": "Hex", "swift": "SwiftURL", "githubactions": "GitHub Actions",
}

// debianReleases names the Debian releases some tools write instead of their number.
var debianReleases = map[string]string{"buster": "10", "bullseye": "11", "bookworm": "12", "trixie": "13", "forky": "14"}

var releaseNumber = regexp.MustCompile(`\d+(\.\d+)?`)

// ParseSBOM reads a CycloneDX or SPDX 2 document, in JSON: the two formats
// syft, trivy, docker sbom and cdxgen write. Only the package URLs are read.
func ParseSBOM(data []byte) (SBOM, error) {
	type property struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	type component struct {
		Type       string      `json:"type"`
		PURL       string      `json:"purl"`
		Properties []property  `json:"properties"`
		Components []component `json:"components"`
	}
	var doc struct {
		BOMFormat   string      `json:"bomFormat"`
		Components  []component `json:"components"`
		SPDXVersion string      `json:"spdxVersion"`
		Packages    []struct {
			SourceInfo   string `json:"sourceInfo"`
			Purpose      string `json:"primaryPackagePurpose"`
			ExternalRefs []struct {
				Type    string `json:"referenceType"`
				Locator string `json:"referenceLocator"`
			} `json:"externalRefs"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return SBOM{}, errors.New("not a JSON document (give a CycloneDX or SPDX SBOM in JSON)")
	}
	out := SBOM{Skipped: map[string]int{}}
	add := func(purl string, src srcPackage) {
		if purl == "" {
			out.Skipped["without a package URL"]++
			return
		}
		c, reason := fromPURL(purl, src)
		switch {
		case reason != "":
			out.Skipped[reason]++
		case !slices.Contains(out.Components, c):
			out.Components = append(out.Components, c)
		}
	}
	switch {
	case doc.BOMFormat == "CycloneDX":
		var walk func([]component)
		walk = func(list []component) {
			for _, c := range list {
				var src srcPackage
				for _, p := range c.Properties { // trivy names the source package this way
					switch p.Name {
					case "aquasecurity:trivy:SrcName":
						src.name = p.Value
					case "aquasecurity:trivy:SrcVersion":
						src.version = p.Value
					case "aquasecurity:trivy:SrcRelease":
						src.release = p.Value
					case "aquasecurity:trivy:SrcEpoch":
						src.epoch = p.Value
					}
				}
				switch {
				case c.Type == "operating-system", c.Type == "container", c.Type == "file":
					// the image and its system, not a package
				case c.PURL != "" || len(c.Components) == 0: // a group of components is not one
					add(c.PURL, src)
				}
				walk(c.Components)
			}
		}
		walk(doc.Components)
	case strings.HasPrefix(doc.SPDXVersion, "SPDX-2"):
		for _, p := range doc.Packages {
			purl := ""
			for _, ref := range p.ExternalRefs {
				if ref.Type == "purl" {
					purl = ref.Locator
				}
			}
			if p.Purpose == "CONTAINER" || p.Purpose == "OPERATING-SYSTEM" || strings.HasPrefix(purl, "pkg:oci/") {
				continue // the image and its system, not a package
			}
			var src srcPackage
			if m := builtFrom.FindStringSubmatch(p.SourceInfo); m != nil {
				src.name, src.full = m[1], m[2]
			}
			add(purl, src)
		}
	default:
		return SBOM{}, errors.New("neither a CycloneDX nor an SPDX 2 document (bomFormat or spdxVersion is missing)")
	}
	slices.SortFunc(out.Components, func(a, b Component) int {
		return cmp.Or(cmp.Compare(a.Ecosystem, b.Ecosystem), cmp.Compare(a.Name, b.Name), cmp.Compare(a.Version, b.Version))
	})
	return out, nil
}

// builtFrom reads the source package trivy writes in an SPDX document.
var builtFrom = regexp.MustCompile(`^built package from: (\S+) (\S+)$`)

// srcPackage is the source package of a distribution package, when the SBOM
// tells it apart from the binary package.
type srcPackage struct {
	name, version, release, epoch string
	full                          string // the whole version, epoch included
}

// fromPURL turns a package URL into the package OSV.dev knows, or tells why
// it cannot be looked up.
func fromPURL(purl string, src srcPackage) (Component, string) {
	rest, ok := strings.CutPrefix(purl, "pkg:")
	if !ok {
		return Component{}, "without a package URL"
	}
	rest, _, _ = strings.Cut(rest, "#")
	rest, query, _ := strings.Cut(rest, "?")
	qualifiers, _ := neturl.ParseQuery(query)
	path, version, _ := strings.Cut(rest, "@")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	for i, p := range parts {
		if u, err := neturl.PathUnescape(p); err == nil {
			parts[i] = u
		}
	}
	if u, err := neturl.PathUnescape(version); err == nil {
		version = u
	}
	kind := strings.ToLower(parts[0])
	if len(parts) < 2 || version == "" {
		return Component{}, "of type " + kind + ", without a name or a version"
	}
	namespace, name := strings.Join(parts[1:len(parts)-1], "/"), parts[len(parts)-1]

	if eco, ok := purlEcosystems[kind]; ok {
		switch {
		case kind == "maven" && namespace != "":
			name = namespace + ":" + name
		case kind == "pypi":
			name = strings.ToLower(strings.NewReplacer("_", "-", ".", "-").Replace(name))
		case namespace != "":
			name = namespace + "/" + name
		}
		if kind == "golang" {
			version = strings.TrimPrefix(version, "v") // go.mod writes v1.2.3, OSV 1.2.3
		}
		return Component{Ecosystem: eco, Name: name, Version: version}, ""
	}

	distro := strings.ToLower(namespace)
	release := strings.ToLower(qualifiers.Get("distro"))
	number := releaseNumber.FindString(release)
	var eco string
	switch kind + "/" + distro {
	case "deb/debian":
		for codename, n := range debianReleases {
			if strings.Contains(release, codename) {
				number = n
			}
		}
		if major, _, _ := strings.Cut(number, "."); major != "" {
			eco = "Debian:" + major
		}
	case "deb/ubuntu":
		if strings.Contains(number, ".") {
			eco = "Ubuntu:" + number
		}
	case "apk/alpine":
		if strings.Contains(number, ".") {
			eco = "Alpine:v" + number
		}
	case "apk/wolfi":
		eco = "Wolfi"
	case "apk/chainguard":
		eco = "Chainguard"
	case "rpm/rocky", "rpm/rockylinux", "rpm/rocky-linux":
		if major, _, _ := strings.Cut(number, "."); major != "" {
			eco = "Rocky Linux:" + major
		}
	case "rpm/almalinux", "rpm/alma":
		if major, _, _ := strings.Cut(number, "."); major != "" {
			eco = "AlmaLinux:" + major
		}
	default:
		return Component{}, "of type " + strings.TrimSuffix(kind+"/"+distro, "/") + ", which OSV.dev does not cover"
	}
	if eco == "" {
		return Component{}, "of type " + kind + "/" + distro + ", without the release of the distribution (distro qualifier)"
	}
	if epoch := qualifiers.Get("epoch"); epoch != "" && !strings.Contains(version, ":") {
		version = epoch + ":" + version
	}
	// The source package: trivy gives it in properties, syft in the upstream
	// qualifier (name, or name@version when the versions differ).
	switch {
	case src.name != "" && src.full != "":
		name, version = src.name, src.full
	case src.name != "":
		name = src.name
		if src.version != "" {
			version = src.version
			if src.release != "" {
				version += "-" + src.release
			}
			if src.epoch != "" && src.epoch != "0" {
				version = src.epoch + ":" + version
			}
		}
	case qualifiers.Get("upstream") != "":
		up, upVersion, _ := strings.Cut(qualifiers.Get("upstream"), "@")
		if file, ok := strings.CutSuffix(up, ".src.rpm"); ok { // name-version-release.src.rpm
			if parts := strings.Split(file, "-"); len(parts) > 2 {
				up = strings.Join(parts[:len(parts)-2], "-")
			}
		}
		name = up
		if upVersion != "" {
			version = upVersion
		}
	}
	return Component{Ecosystem: eco, Name: name, Version: version}, ""
}

// SkippedNote tells in one sentence what an SBOM lists that is not looked
// up, or "" when everything is.
func (s SBOM) SkippedNote() string {
	var parts []string
	for reason, n := range s.Skipped {
		parts = append(parts, fmt.Sprintf("%d %s", n, reason))
	}
	slices.Sort(parts)
	return strings.Join(parts, "; ")
}

// inEcosystem tells whether an OSV ecosystem ("Debian:12", "Ubuntu:22.04:LTS")
// is, or is a release of, the one given ("Debian", "Ubuntu:22.04").
func inEcosystem(ecosystem, of string) bool {
	return ecosystem == of || strings.HasPrefix(ecosystem, of+":")
}

// isDistribution tells whether an OSV ecosystem is a Linux distribution: its
// versions follow rules of their own, so OSV.dev's answer is trusted rather
// than compared again.
func isDistribution(ecosystem string) bool {
	name, _, _ := strings.Cut(ecosystem, ":")
	return slices.Contains([]string{"Debian", "Ubuntu", "Alpine", "Wolfi", "Chainguard", "Rocky Linux", "AlmaLinux"}, name)
}
