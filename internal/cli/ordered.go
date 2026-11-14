package cli

import "strings"

// orderedList is a repeatable, comma-separated flag that also records each
// value in a list shared with other flags: --tag and --keyword fill their own
// list and one common order, which pflag does not keep across flags.
type orderedList struct {
	values *[]string
	order  *[]string
}

func (o orderedList) Set(s string) error {
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			*o.values = append(*o.values, v)
			*o.order = append(*o.order, v)
		}
	}
	return nil
}

func (o orderedList) String() string {
	if o.values == nil {
		return ""
	}
	return strings.Join(*o.values, ",")
}

func (o orderedList) Type() string { return "strings" }
