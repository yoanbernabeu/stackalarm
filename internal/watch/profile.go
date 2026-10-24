// Package watch holds what a scheduled watch needs between two runs: the
// project profile the agent writes, and the state of what was reported.
package watch

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// Profile is what the agent learned about a project: the tags, keywords and
// packages to watch, and the stack they come from. The CLI does no project
// analysis; it only reads what the agent wrote.
type Profile struct {
	Tags     []string    `yaml:"tags,omitempty" json:"tags,omitempty"`
	Keywords []string    `yaml:"keywords,omitempty" json:"keywords,omitempty"`
	Packages []string    `yaml:"packages,omitempty" json:"packages,omitempty"`
	Stack    []Component `yaml:"stack,omitempty" json:"stack,omitempty"` // shown in reports, never used to filter
}

// Component is one technology of the project and the version found for it.
type Component struct {
	Name      string `yaml:"name" json:"name"`
	Version   string `yaml:"version,omitempty" json:"version,omitempty"`
	Precision string `yaml:"precision,omitempty" json:"precision,omitempty"` // exact, branch, range or unknown
	From      string `yaml:"from,omitempty" json:"from,omitempty"`           // the file it was read from
}

var precisions = []string{"exact", "branch", "range", "unknown"}

// LoadProfile reads and validates a profile file.
func LoadProfile(path string) (Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Profile{}, err
	}
	p, err := ParseProfile(data)
	if err != nil {
		return Profile{}, fmt.Errorf("%s: %w", path, err)
	}
	return p, nil
}

// ParseProfile reads one profile and reports every problem at once.
func ParseProfile(data []byte) (Profile, error) {
	var p Profile
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return Profile{}, fmt.Errorf("invalid YAML: %w", err)
	}
	var errs []error
	if len(p.Tags) == 0 && len(p.Keywords) == 0 {
		errs = append(errs, errors.New("a profile needs tags or keywords to watch"))
	}
	for i, c := range p.Stack {
		if c.Name == "" {
			errs = append(errs, fmt.Errorf("stack[%d]: name is required", i))
		}
		if c.Precision != "" && !slices.Contains(precisions, c.Precision) {
			errs = append(errs, fmt.Errorf("stack[%d]: precision %q must be one of %v", i, c.Precision, precisions))
		}
	}
	return p, errors.Join(errs...)
}
