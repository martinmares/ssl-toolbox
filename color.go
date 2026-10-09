package main

import (
	"fmt"
	"golang.org/x/term"
	"io"
	"os"
)

func colorEnabled(w io.Writer, mode string) (bool, error) {
	switch mode {
	case "always":
		return true, nil
	case "never":
		return false, nil
	case "auto":
		file, ok := w.(*os.File)
		_, noColor := os.LookupEnv("NO_COLOR")
		return ok && term.IsTerminal(int(file.Fd())) && !noColor && os.Getenv("TERM") != "dumb", nil
	default:
		return false, fmt.Errorf("--color must be auto, always or never")
	}
}

func paintANSI(text, code string, color bool) string {
	if !color {
		return text
	}
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}
