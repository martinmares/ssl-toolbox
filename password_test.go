package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"software.sslmate.com/src/go-pkcs12"
)

func TestPasswordFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "password")
	for _, tt := range []struct{ content, want string }{{" secret ", " secret "}, {"secret\n", "secret"}, {"secret\r\n", "secret"}, {"", ""}, {"secret\n\n", "secret\n"}} {
		if err := os.WriteFile(path, []byte(tt.content), 0600); err != nil {
			t.Fatal(err)
		}
		got, err := readPasswordSource("", path, "", &bytes.Buffer{})
		if err != nil || got != tt.want {
			t.Fatalf("file password changed: %v", err)
		}
	}
	t.Setenv("PASS_TEST", "secret\n")
	if got, err := readPasswordSource("PASS_TEST", "", "", &bytes.Buffer{}); err != nil || got != "secret\n" {
		t.Fatal("environment value changed")
	}
	for _, source := range [][2]string{{"PASS_TEST", path}, {"MISSING_PASS_TEST", ""}, {"", path + "missing"}} {
		if _, err := readPasswordSource(source[0], source[1], "", &bytes.Buffer{}); err == nil {
			t.Fatal("accepted invalid source")
		}
	}
}

func TestPipelinePasswordSources(t *testing.T) {
	// A pipe ensures no terminal can satisfy an accidental prompt.
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	writer.Close()
	original := os.Stdin
	os.Stdin = reader
	t.Cleanup(func() { os.Stdin = original; reader.Close() })
	dir := t.TempDir()
	oldFile, newFile := filepath.Join(dir, "old-password"), filepath.Join(dir, "new-password")
	for path, value := range map[string]string{oldFile: "old-secret\n", newFile: "new-secret\r\n"} {
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PIPELINE_OLD", "old-secret")
	t.Setenv("PIPELINE_NEW", "new-secret")
	key, cert, ca := fixture(t)
	data, err := pkcs12.LegacyRC2.Encode(key, cert, []*x509.Certificate{ca}, "old-secret")
	if err != nil {
		t.Fatal(err)
	}
	in, caFile := filepath.Join(dir, "in.pfx"), filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(in, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"env", "file"} {
		flags := []string{"--in-pass-env", "PIPELINE_OLD", "--out-pass-env", "PIPELINE_NEW"}
		inspectFlags := []string{"--pass-env", "PIPELINE_NEW"}
		trustFlags := []string{"--out-pass-env", "PIPELINE_NEW"}
		if mode == "file" {
			flags = []string{"--in-pass-file", oldFile, "--out-pass-file", newFile}
			inspectFlags = []string{"--pass-file", newFile}
			trustFlags = []string{"--out-pass-file", newFile}
		}
		out := filepath.Join(dir, mode+".pfx")
		var output, diagnostics bytes.Buffer
		args := append([]string{"convert", "--in", in, "--out", out}, flags...)
		if err := run(args, &output, &diagnostics); err != nil {
			t.Fatal(err)
		}
		converted, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		got, _, _, err := pkcs12.DecodeChain(converted, "new-secret")
		if err != nil || !key.Equal(got) {
			t.Fatalf("new password failed: %v", err)
		}
		if err := run(append([]string{"inspect", out, "--json"}, inspectFlags...), &output, &diagnostics); err != nil {
			t.Fatal(err)
		}
		trust := filepath.Join(dir, mode+"-trust.pfx")
		if err := run(append([]string{"truststore", "--add-ca", caFile, "--out", trust}, trustFlags...), &output, &diagnostics); err != nil {
			t.Fatal(err)
		}
		if err := run(append([]string{"inspect", trust}, inspectFlags...), &output, &diagnostics); err != nil {
			t.Fatal(err)
		}
		if diagnostics.Len() != 0 || strings.Contains(output.String(), "new-secret") || strings.Contains(output.String(), "old-secret") {
			t.Fatal("prompt or password leak")
		}
	}
	if _, err := readPasswordSource("", "", "Password: ", &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "without a terminal") {
		t.Fatal("missing CI password not rejected")
	}
	if err := os.WriteFile(newFile, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"truststore", "--add-ca", caFile, "--out", filepath.Join(dir, "empty.pfx"), "--out-pass-file", newFile}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("accepted empty new password")
	}
	for _, args := range [][]string{
		{"inspect", in, "--pass-env", "PIPELINE_OLD", "--pass-file", oldFile},
		{"inspect", in, "--key-pass-env", "PIPELINE_OLD", "--key-pass-file", oldFile},
		{"convert", "--in", in, "--out", filepath.Join(dir, "conflict.pfx"), "--in-pass-env", "PIPELINE_OLD", "--in-pass-file", oldFile},
		{"truststore", "--out", filepath.Join(dir, "conflict-trust.pfx"), "--add-ca", caFile, "--out-pass-env", "PIPELINE_NEW", "--out-pass-file", newFile},
	} {
		if err := run(args, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
			t.Fatal("accepted conflicting password sources")
		}
	}
}
