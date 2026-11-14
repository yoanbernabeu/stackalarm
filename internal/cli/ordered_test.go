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
