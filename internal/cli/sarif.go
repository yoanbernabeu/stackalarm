package cli

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/yoanbernabeu/stackalarm/internal/news"
	"github.com/yoanbernabeu/stackalarm/internal/source"
)

var sarifCVE = regexp.MustCompile(`CVE-\d{4}-\d+`)

// proven tells whether a version in use proves the item concerns the
// project: a range that holds it, or a component past its end of life.
func proven(it news.Item) bool {
	return it.Source == news.SupportSource ||
		slices.ContainsFunc(it.Affected, func(a news.Affected) bool { return a.Status == news.StatusAffected })
}

// printSARIF writes the proven items as SARIF 2.1.0, for the code scanning
// dashboards of GitHub and GitLab. The rest of the report is raw news that
// only a reader can judge: it has no place among confirmed findings. Every
// result points at the profile, the file that says what the project runs.
func (a *App) printSARIF(r newsReport, profile string) error {
	type text struct {
		Text string `json:"text"`
	}
	type rule struct {
		ID      string `json:"id"`
		Short   text   `json:"shortDescription"`
		HelpURI string `json:"helpUri,omitempty"`
	}
	type location struct {
		Physical struct {
			Artifact struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
			Region struct {
				StartLine int `json:"startLine"`
			} `json:"region"`
		} `json:"physicalLocation"`
	}
	type result struct {
		RuleID       string            `json:"ruleId"`
		Level        string            `json:"level"`
		Message      text              `json:"message"`
		Locations    []location        `json:"locations"`
		Fingerprints map[string]string `json:"partialFingerprints"`
	}
	rules, results := []rule{}, []result{}
	for _, it := range r.Items {
		if !proven(it) {
			continue
		}
		id := "stackalarm-" + it.ID
		if cves := sarifCVE.FindAllString(it.Title, -1); len(cves) > 0 {
			id = cves[len(cves)-1] // a title may name an earlier CVE; its own id closes it
		}
		level := "warning"
		if it.Stage == source.StageAlert || len(it.ExploitedIn) > 0 || len(it.PublicExploitIn) > 0 || it.Score >= 9 {
			level = "error"
		}
		msg := it.Title
		if aff := affected(it); aff != "" {
			msg += ". Affects " + aff
		}
		if len(it.ExploitedIn) > 0 {
			msg += ". Exploited in the wild (" + strings.Join(it.ExploitedIn, ", ") + ")"
		}
		if len(it.PublicExploitIn) > 0 {
			msg += ". Public exploit (" + strings.Join(it.PublicExploitIn, ", ") + ")"
		}
		if !slices.ContainsFunc(rules, func(r rule) bool { return r.ID == id }) {
			rules = append(rules, rule{ID: id, Short: text{it.Title}, HelpURI: it.URL})
		}
		var loc location
		loc.Physical.Artifact.URI, loc.Physical.Region.StartLine = profile, 1
		results = append(results, result{
			RuleID: id, Level: level, Message: text{msg + "."}, Locations: []location{loc},
			Fingerprints: map[string]string{"stackalarm/v1": it.ID},
		})
	}
	doc := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"tool": map[string]any{"driver": map[string]any{
				"name": "stackalarm", "informationUri": "https://stackalarm.dev", "version": a.Version, "rules": rules,
			}},
			"results": results,
		}},
	}
	enc := json.NewEncoder(a.Out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return err
	}
	for _, f := range r.Failures { // a SARIF file has no place for them, and they are never silent
		fmt.Fprintf(a.Err, "Warning: %s could not be read: %s\n", f.Source, f.Error)
	}
	return nil
}
