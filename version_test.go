package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestVersionCLI(t *testing.T) {
	data, err := os.ReadFile("VERSION")
	if err != nil {
		t.Fatal(err)
	}
	want := strings.TrimSpace(string(data))
	if want == "" {
		t.Fatal("VERSION is empty")
	}
	for _, args := range [][]string{{"--version"}, {"version"}} {
		var output bytes.Buffer
		if err := run(args, &output, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(output.String(), "ssl-toolbox version "+want+"\n") {
			t.Fatalf("VERSION not used: %s", &output)
		}
	}
	oldVersion, oldCommit, oldDate := version, commit, buildDate
	t.Cleanup(func() { version, commit, buildDate = oldVersion, oldCommit, oldDate })
	version, commit, buildDate = "2.3.4-test", "abc123", "2026-10-08T00:00:00Z"
	var output bytes.Buffer
	if err := run([]string{"version"}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"2.3.4-test", "abc123", "2026-10-08T00:00:00Z"} {
		if !strings.Contains(output.String(), value) {
			t.Fatalf("missing build metadata %s", value)
		}
	}
}
