package watch

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// Retention is how long a reported item is remembered. It is longer than any
// sensible --since window, so an item cannot come back once forgotten.
const Retention = 90 * 24 * time.Hour

// State remembers the items already reported, one "id date" line each. Losing
// it only means reporting a few items twice, never missing one.
type State struct {
	seen map[string]time.Time
}

// LoadState reads a state file. A missing file is an empty state: the first
// run of a watch, or a CI cache that expired.
func LoadState(path string) (State, error) {
	s := State{seen: map[string]time.Time{}}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		id, date, ok := strings.Cut(line, " ")
		at, err := time.Parse(time.DateOnly, strings.TrimSpace(date))
		if !ok || err != nil {
			return s, fmt.Errorf("%s:%d: want \"<id> <YYYY-MM-DD>\", got %q", path, n, line)
		}
		s.seen[id] = at
	}
	return s, sc.Err()
}

// Seen tells whether an item was already reported.
func (s State) Seen(id string) bool {
	_, ok := s.seen[id]
	return ok
}

// Add records an item as reported at the given time.
func (s *State) Add(id string, at time.Time) {
	if s.seen == nil {
		s.seen = map[string]time.Time{}
	}
	if _, ok := s.seen[id]; !ok {
		s.seen[id] = at.UTC().Truncate(24 * time.Hour)
	}
}

// Save writes the state, forgetting the items older than Retention. The file
// is replaced atomically, so an interrupted run leaves the previous state.
func (s State) Save(path string, now time.Time) error {
	var b strings.Builder
	b.WriteString("# stackalarm: items already reported by the scheduled watch\n")
	for _, id := range slices.Sorted(maps.Keys(s.seen)) {
		if at := s.seen[id]; now.Sub(at) <= Retention {
			fmt.Fprintf(&b, "%s %s\n", id, at.Format(time.DateOnly))
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".stackalarm-state-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // a no-op once renamed
	if _, err := tmp.WriteString(b.String()); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
