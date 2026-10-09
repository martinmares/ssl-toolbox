//go:build ignore

// Run with: go run scripts/update_notices.go
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

type module struct {
	Path, Version, Dir string
	Main               bool
	Replace            *module
}
type pkg struct{ Module *module }

func main() {
	if err := updateNotices(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func updateNotices() error {
	modules := map[string]*module{}
	// Windows adds mousetrap, which is absent from Unix dependency lists.
	for _, target := range []string{"linux/amd64", "darwin/arm64", "windows/amd64"} {
		parts := strings.Split(target, "/")
		cmd := exec.Command("go", "list", "-deps", "-json", ".")
		for _, entry := range os.Environ() {
			if !strings.HasPrefix(entry, "GOOS=") && !strings.HasPrefix(entry, "GOARCH=") && !strings.HasPrefix(entry, "CGO_ENABLED=") {
				cmd.Env = append(cmd.Env, entry)
			}
		}
		cmd.Env = append(cmd.Env, "GOOS="+parts[0], "GOARCH="+parts[1], "CGO_ENABLED=0")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		output, err := cmd.Output()
		if err != nil {
			return fmt.Errorf("list %s dependencies: %w: %s", target, err, &stderr)
		}
		decoder := json.NewDecoder(bytes.NewReader(output))
		for {
			var p pkg
			err := decoder.Decode(&p)
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
			if p.Module != nil && !p.Module.Main {
				modules[p.Module.Path] = p.Module
			}
		}
	}
	var result bytes.Buffer
	fmt.Fprintln(&result, "# Third-party notices\n\nThe project code is MIT licensed. The following components retain their own\nlicenses and copyright notices. Distribute this file with release binaries.\nRegenerate with `just notices` after changing dependencies.\n")
	// The Go runtime and standard library are part of every release binary.
	goLicenseDir := runtime.GOROOT()
	// Homebrew installs LICENSE beside libexec rather than inside GOROOT.
	if _, err := os.Stat(filepath.Join(goLicenseDir, "LICENSE")); os.IsNotExist(err) && filepath.Base(goLicenseDir) == "libexec" {
		goLicenseDir = filepath.Dir(goLicenseDir)
	}
	if err := appendLicenses(&result, "Go runtime and standard library", runtime.Version(), goLicenseDir); err != nil {
		return err
	}
	paths := make([]string, 0, len(modules))
	for path := range modules {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		m := modules[path]
		label := m.Version
		if m.Replace != nil {
			label += " (local modified copy)"
		}
		if err := appendLicenses(&result, path, label, m.Dir); err != nil {
			return err
		}
	}
	return os.WriteFile("THIRD_PARTY_NOTICES.md", []byte(strings.TrimRight(result.String(), "\n")+"\n"), 0644)
}

func appendLicenses(w io.Writer, name, version, dir string) error {
	files, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var notices []string
	for _, file := range files {
		upper := strings.ToUpper(file.Name())
		if !file.IsDir() && (upper == "LICENSE" || strings.HasPrefix(upper, "LICENSE.") || upper == "COPYING" || upper == "NOTICE" || strings.HasPrefix(upper, "NOTICE.")) {
			notices = append(notices, file.Name())
		}
	}
	if len(notices) == 0 {
		return fmt.Errorf("no license found for %s in %s", name, dir)
	}
	fmt.Fprintf(w, "## %s %s\n\n", name, version)
	for _, file := range notices {
		data, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "### %s\n\n```text\n%s\n```\n\n", file, strings.TrimSpace(string(data)))
	}
	return nil
}
