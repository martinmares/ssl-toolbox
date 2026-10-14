package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

type failingWriter struct{}

func (failingWriter) Write(p []byte) (int, error) { return 0, errors.New("broken output") }

func TestExamplesOutput(t *testing.T) {
	for _, mode := range []string{"auto", "never", "always"} {
		var output bytes.Buffer
		if err := run([]string{"examples", "--color", mode}, &output, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
		text := output.String()
		if strings.Contains(text, "\x1b[") != (mode == "always") {
			t.Fatal("incorrect ANSI mode")
		}
		for _, part := range []string{"## CSR CREATE", "## CSR BATCH", "FILE · requests.yaml", "passwordEnv: KEY_PASSWORD", "## PFX CREATE", "--sans-file", "FILE · dns-names.txt", "--out-dir", "--chain", "## INSPECT", "## CONFIGMAP EXTRACT-BINARY", "--key-pass-env", "--json", "## CONVERT", "## TRUSTSTORE", "## CONFIGMAP SET-BINARY", "--dry-run", "--create", "--add-ca", "FILE · assets.yml", ".bak", "manifests/configmap.yaml"} {
			if !strings.Contains(text, part) {
				t.Fatalf("missing %s", part)
			}
		}
	}
	if err := run([]string{"examples", "--color", "bad"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("accepted invalid color mode")
	}
	if err := writeExamples(failingWriter{}, false); err == nil {
		t.Fatal("ignored output error")
	}
}
