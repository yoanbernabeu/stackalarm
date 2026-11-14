package cli

import (
	"strings"
	"testing"

	"github.com/yoanbernabeu/stackalarm/internal/news"
)

func TestTagsAndKeywordsShareOneOrder(t *testing.T) {
	var tags, keywords, order []string
	tag, keyword := orderedList{&tags, &order}, orderedList{&keywords, &order}
	tag.Set("php@8.3.35")
	keyword.Set("dompdf, libwebp")
	tag.Set("nextjs")
	if strings.Join(order, ",") != "php@8.3.35,dompdf,libwebp,nextjs" || strings.Join(tags, ",") != "php@8.3.35,nextjs" || keyword.String() != "dompdf,libwebp" {
		t.Fatalf("order %v, tags %v, keywords %v", order, tags, keywords)
	}
}

func TestCloseTags(t *testing.T) {
	known := []string{"gitlab", "github-actions", "node", "nodemailer", "php"}
	if got := closeTags("gitlab-runner", known); got != "close tags: gitlab; run stackalarm sources to see them all" {
		t.Fatalf("got %q", got)
	}
	if got := closeTags("zz", known); got != "run stackalarm sources to see the tags" {
		t.Fatalf("got %q", got)
	}
}

func TestAFixOnALaterMajorVersionIsSaid(t *testing.T) {
	it := news.Item{Affected: []news.Affected{{Package: "node", Versions: "< 22.23.4", Fixed: "22.23.4", InUse: "20.20.2", Status: news.StatusAffected}}}
	if got := affected(it); got != "node < 22.23.4 (fixed in 22.23.4, not on the 20 branch: upgrade the branch) [20.20.2 in use: AFFECTED]" {
		t.Fatalf("got %q", got)
	}
	it.Affected[0].InUse, it.Affected[0].Fixed = "22.20.0", "22.23.4"
	if got := affected(it); strings.Contains(got, "branch") {
		t.Fatalf("a fix on the same major version is a patch: %q", got)
	}
}
