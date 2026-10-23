// Package sources embeds the source definitions shipped with stackalarm.
package sources

import "embed"

// FS holds every source definition (*.yaml).
//
//go:embed *.yaml
var FS embed.FS
