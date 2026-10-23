// Command stackalarm gathers the security news of the technologies you use.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"github.com/yoanbernabeu/stackalarm/internal/cli"
)

// version is set at build time.
var version = "dev"

func main() {
	if info, ok := debug.ReadBuildInfo(); ok && version == "dev" && info.Main.Version != "" && info.Main.Version != "(devel)" {
		version = info.Main.Version // go install …@v0.1.0
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	app, err := cli.Default(version)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
	code := app.Execute(ctx)
	stop()
	os.Exit(code)
}
