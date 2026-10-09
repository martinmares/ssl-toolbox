package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractBinaryRoundTrip(t *testing.T) {
	for _, payload := range [][]byte{{0, 255, 128, '\n', 1}, {}} {
		dir := t.TempDir()
		manifest, out := filepath.Join(dir, "assets.yml"), filepath.Join(dir, "out.jks")
		original := []byte("# preserve me\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: kafka\n  namespace: prod\nbinaryData:\n  client.jks: '" + base64.StdEncoding.EncodeToString(payload) + "'\n")
		if err := os.WriteFile(manifest, original, 0644); err != nil {
			t.Fatal(err)
		}
		var output bytes.Buffer
		args := []string{"configmap", "extract-binary", manifest, "client.jks", "--out", out}
		if err := run(args, &output, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(out)
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("bytes changed: %x %v", got, err)
		}
		unchanged, _ := os.ReadFile(manifest)
		if !bytes.Equal(original, unchanged) {
			t.Fatal("manifest changed")
		}
		info, _ := os.Stat(out)
		if info.Mode().Perm() != 0600 {
			t.Fatalf("permissions: %v", info.Mode())
		}
		if !strings.Contains(output.String(), "SHA-256:") {
			t.Fatal("missing fingerprint")
		}
		if err := run(args, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
			t.Fatal("overwrote output")
		}
		if _, err := os.Stat(manifest + ".bak"); !os.IsNotExist(err) {
			t.Fatal("created backup")
		}
	}
}

func TestExtractBinaryValidation(t *testing.T) {
	prefix := "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: kafka\n"
	for name, yaml := range map[string]string{
		"missing":   prefix,
		"base64":    prefix + "binaryData:\n  key: invalid!\n",
		"nonstring": prefix + "binaryData:\n  key: 12\n",
		"duplicate": prefix + "binaryData:\n  key: YQ==\n  key: Yg==\n",
		"anchor":    prefix + "binaryData:\n  key: &key YQ==\n",
		"conflict":  prefix + "binaryData:\n  key: YQ==\ndata:\n  key: a\n",
		"ambiguous": prefix + "binaryData:\n  key: YQ==\n---\n" + prefix + "binaryData:\n  key: YQ==\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			manifest, out := filepath.Join(dir, "m.yml"), filepath.Join(dir, "out")
			if err := os.WriteFile(manifest, []byte(yaml), 0600); err != nil {
				t.Fatal(err)
			}
			if err := run([]string{"configmap", "extract-binary", manifest, "key", "--out", out}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
				t.Fatal("accepted invalid manifest")
			}
			if _, err := os.Stat(out); !os.IsNotExist(err) {
				t.Fatal("wrote output on failure")
			}
		})
	}
	t.Run("selection", func(t *testing.T) {
		dir := t.TempDir()
		manifest, out := filepath.Join(dir, "m.yml"), filepath.Join(dir, "out")
		yaml := prefix + "binaryData:\n  key: YQ==\n---\n" + strings.Replace(prefix, "name: kafka", "name: other", 1) + "binaryData:\n  key: Yg==\n"
		if err := os.WriteFile(manifest, []byte(yaml), 0600); err != nil {
			t.Fatal(err)
		}
		if err := run([]string{"configmap", "extract-binary", manifest, "key", "--out", out, "--name", "other"}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
		data, _ := os.ReadFile(out)
		if string(data) != "b" {
			t.Fatal("wrong selection")
		}
	})
}
