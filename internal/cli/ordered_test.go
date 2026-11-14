package cli

import (
	"strings"
	"testing"
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
