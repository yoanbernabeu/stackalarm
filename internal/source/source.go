// Package source defines the watched sources: one YAML file per source in
// the sources/ directory.
package source

import (
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// Type is how a source is read.
type Type string

// Source types.
const (
	TypeFeed             Type = "feed"              // RSS 2.0, RSS 1.0 (RDF) or Atom
	TypeGitHubAdvisories Type = "github-advisories" // published security advisories of a GitHub repository
	TypeKEV              Type = "kev"               // CISA Known Exploited Vulnerabilities catalog
	// TypeGitHubAdvisoryDatabase reads the reviewed advisories of one ecosystem
	// from the GitHub Advisory Database.
	TypeGitHubAdvisoryDatabase Type = "github-advisory-database"
	TypeEUVD                   Type = "euvd"        // a list from the ENISA EU Vulnerability Database API
	TypeEUVDSearch             Type = "euvd-search" // ENISA EUVD, searched for each requested word
	TypeNVD                    Type = "nvd"         // NIST NVD, searched for each requested word
)

// IsSearch tells whether the source is queried with the requested words
// rather than read as a whole. Search sources are skipped without words.
func (t Type) IsSearch() bool { return t == TypeEUVDSearch || t == TypeNVD }

// Stage is the step of the security timeline a source reveals.
type Stage string

// Stages, in the order they usually happen.
const (
	StageHeadsUp  Stage = "heads-up" // a security release is announced ahead
	StageRelease  Stage = "release"  // a release with security fixes is out
	StageAdvisory Stage = "advisory" // detailed advisories (CVE, affected versions)
	StageAlert    Stage = "alert"    // a CERT alert, a public exploit, or exploitation in the wild
	StageNews     Stage = "news"     // security press and research: context, never the only evidence
)

// General is the tag of sources that cover every technology (CERTs, KEV…).
// Their entries are kept only when they mention one of the requested tags.
const General = "general"

// Source is one watched source.
type Source struct {
	ID        string   `yaml:"id" json:"id"`
	Name      string   `yaml:"name" json:"name"`
	Type      Type     `yaml:"type" json:"type"`
	URL       string   `yaml:"url,omitempty" json:"url,omitempty"`
	Repo      string   `yaml:"repo,omitempty" json:"repo,omitempty"`           // owner/name, for github-advisories
	Ecosystem string   `yaml:"ecosystem,omitempty" json:"ecosystem,omitempty"` // for github-advisory-database (npm, composer, pip…)
	Tags      []string `yaml:"tags" json:"tags"`
	Stage     Stage    `yaml:"stage" json:"stage"`
	Keywords  []string `yaml:"keywords,omitempty" json:"keywords,omitempty"` // keep only entries containing one of them
	Language  string   `yaml:"language,omitempty" json:"language,omitempty"` // when not English
}

var (
	idPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	tagPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.+-]*$`)
	types      = []Type{TypeFeed, TypeGitHubAdvisories, TypeKEV, TypeGitHubAdvisoryDatabase, TypeEUVD, TypeEUVDSearch, TypeNVD}
)

// Stages lists every stage, in the order they usually happen.
var Stages = []Stage{StageHeadsUp, StageRelease, StageAdvisory, StageAlert, StageNews}

// Parse reads and validates one source definition.
func Parse(data []byte) (Source, error) {
	var s Source
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&s); err != nil {
		return Source{}, fmt.Errorf("invalid YAML: %w", err)
	}
	return s, s.Validate()
}

// Validate checks a source and reports every problem at once.
func (s Source) Validate() error {
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	if !idPattern.MatchString(s.ID) {
		fail("id %q must be lowercase letters, digits and dashes", s.ID)
	}
	if s.Name == "" {
		fail("name is required")
	}
	if !slices.Contains(types, s.Type) {
		fail("type %q must be one of %v", s.Type, types)
	}
	if !slices.Contains(Stages, s.Stage) {
		fail("stage %q must be one of %v", s.Stage, Stages)
	}
	if len(s.Tags) == 0 {
		fail("tags are required (use %q for a source that covers everything)", General)
	}
	for _, t := range s.Tags {
		if !tagPattern.MatchString(t) {
			fail("tag %q must be lowercase", t)
		}
	}
	switch s.Type {
	case TypeGitHubAdvisories:
		if strings.Count(s.Repo, "/") != 1 || s.URL != "" || s.Ecosystem != "" {
			fail("a github-advisories source needs repo: owner/name, and no url nor ecosystem")
		}
	case TypeGitHubAdvisoryDatabase:
		if s.Ecosystem == "" || s.URL != "" || s.Repo != "" {
			fail("a github-advisory-database source needs ecosystem, and no url nor repo")
		}
	default:
		if !strings.HasPrefix(s.URL, "https://") {
			fail("url must start with https://")
		}
		if s.Repo != "" || s.Ecosystem != "" {
			fail("repo and ecosystem are only for GitHub sources")
		}
		if s.Type.IsSearch() && !s.IsGeneral() {
			fail("a search source must be tagged %q: it is queried with the requested words", General)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("source %q: %w", s.ID, errors.Join(errs...))
	}
	return nil
}

// IsGeneral tells whether the source covers every technology.
func (s Source) IsGeneral() bool { return slices.Contains(s.Tags, General) }

// LoadAll reads every *.yaml file at the root of fsys. File names must match
// the ids.
func LoadAll(fsys fs.FS) ([]Source, error) {
	names, err := fs.Glob(fsys, "*.yaml")
	if err != nil {
		return nil, err
	}
	var (
		out  []Source
		errs []error
	)
	for _, name := range names {
		if name == SearchFile {
			continue
		}
		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, err
		}
		s, err := Parse(data)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
			continue
		}
		if want := strings.TrimSuffix(name, ".yaml"); s.ID != want {
			errs = append(errs, fmt.Errorf("%s: id %q must match the file name", name, s.ID))
			continue
		}
		out = append(out, s)
	}
	return out, errors.Join(errs...)
}

// SearchFile sits next to the sources but is not one: it says how the CVE
// databases are searched for each tag.
const SearchFile = "search.yaml"

// Search tunes the words the search sources (NVD, EUVD) are queried with.
type Search struct {
	// Aliases replace an ambiguous tag, in searches and when matching the
	// entries of general sources: "node" alone matches Linux kernel CVEs.
	Aliases map[string]string `yaml:"aliases"`
	// Skip lists the tags the search sources are not queried with: the word
	// means something else, or names a whole ecosystem whose own sources
	// already cover the project. General sources still match them.
	Skip []string `yaml:"skip"`
}

// LoadSearch reads SearchFile and checks that it only names tags of sources.
func LoadSearch(fsys fs.FS, sources []Source) (Search, error) {
	data, err := fs.ReadFile(fsys, SearchFile)
	if err != nil {
		return Search{}, err
	}
	var s Search
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&s); err != nil {
		return Search{}, fmt.Errorf("%s: invalid YAML: %w", SearchFile, err)
	}
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }
	tags := Tags(sources)
	for tag, alias := range s.Aliases {
		if !slices.Contains(tags, tag) {
			fail("alias of unknown tag %q", tag)
		}
		if alias == "" || alias != strings.ToLower(alias) {
			fail("alias of %q must be a lowercase word", tag)
		}
		if slices.Contains(s.Skip, tag) {
			fail("tag %q is both aliased and skipped", tag)
		}
	}
	for _, tag := range s.Skip {
		if !slices.Contains(tags, tag) || tag == General {
			fail("skipped tag %q is not a technology tag of a source", tag)
		}
	}
	if len(errs) > 0 {
		return Search{}, fmt.Errorf("%s: %w", SearchFile, errors.Join(errs...))
	}
	return s, nil
}

// Tags returns every tag used by the sources, sorted.
func Tags(sources []Source) []string {
	var out []string
	for _, s := range sources {
		out = append(out, s.Tags...)
	}
	slices.Sort(out)
	return slices.Compact(out)
}
