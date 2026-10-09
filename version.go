package main

import (
	_ "embed"
	"fmt"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

//go:embed VERSION
var versionFile string

// Justfile supplies build metadata through -ldflags; VERSION also works for
// a plain go build, including source archives without Git metadata.
var (
	version   string
	commit    = "unknown"
	buildDate = "unknown"
)

func currentVersion() string {
	if strings.TrimSpace(version) != "" {
		return strings.TrimSpace(version)
	}
	return strings.TrimSpace(versionFile)
}

func newVersionCommand() *cobra.Command {
	return &cobra.Command{Use: "version", Short: "Print version and build metadata", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "ssl-toolbox version %s\ncommit: %s\nbuilt: %s\ngo: %s\nplatform: %s/%s\n", currentVersion(), commit, buildDate, runtime.Version(), runtime.GOOS, runtime.GOARCH)
			return err
		},
	}
}
