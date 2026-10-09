package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const cmFixture = `# retained leading comment
apiVersion: v1
kind: ConfigMap
metadata:
  name: kafka
  namespace: prod
binaryData:
  client.jks: b2xk # retain inline comment
  other.bin: AAEC
data:
  text: unchanged
---
# other document
apiVersion: v1
kind: Service
metadata:
  name: untouched
`

func TestConfigMapUpdatePreservesContent(t *testing.T) {
	payload := []byte{0, 255, 1, 2, 3}
	out, change, err := updateConfigMap([]byte(cmFixture), payload, configMapOptions{key: "client.jks"})
	if err != nil {
		t.Fatal(err)
	}
	if !change.changed || change.oldSize != 3 || change.newSize != len(payload) {
		t.Fatalf("bad summary: %+v", change)
	}
	for _, text := range []string{"retained leading comment", "retain inline comment", "other document", "other.bin: AAEC", "text: unchanged", "name: untouched"} {
		if !strings.Contains(string(out), text) {
			t.Fatalf("lost %s", text)
		}
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	got := scalarField(mapField(doc.Content[0], "binaryData"), "client.jks")
	decoded, err := base64.StdEncoding.DecodeString(got)
	if err != nil || !bytes.Equal(decoded, payload) {
		t.Fatal("replacement is not the raw file bytes")
	}
	if _, _, err := updateConfigMap(out, payload, configMapOptions{key: "client.jks"}); err != nil {
		t.Fatal(err)
	}
}

func TestConfigMapSelectionAndValidation(t *testing.T) {
	multi := cmFixture + "---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: kafka\n  namespace: dev\nbinaryData:\n  client.jks: ZGV2\n"
	if _, _, err := updateConfigMap([]byte(multi), []byte("new"), configMapOptions{key: "client.jks", name: "kafka"}); err == nil {
		t.Fatal("accepted ambiguous selection")
	}
	out, change, err := updateConfigMap([]byte(multi), []byte("new"), configMapOptions{key: "client.jks", name: "kafka", namespace: "dev"})
	if err != nil || change.namespace != "dev" || !bytes.Contains(out, []byte("client.jks: b2xk")) {
		t.Fatalf("selection failed: %v", err)
	}
	for name, input := range map[string]string{
		"duplicate":        strings.Replace(cmFixture, "  other.bin: AAEC", "  client.jks: AAEC", 1),
		"bad base64":       strings.Replace(cmFixture, "b2xk", "!!bad!!", 1),
		"data conflict":    strings.Replace(cmFixture, "  text: unchanged", "  client.jks: text", 1),
		"anchored mapping": strings.Replace(cmFixture, "binaryData:", "binaryData: &shared", 1),
		"alias":            strings.Replace(cmFixture, "  client.jks: b2xk", "  client.jks: &payload b2xk", 1),
		"missing name":     strings.Replace(cmFixture, "  name: kafka\n", "", 1),
		"malformed":        "[unterminated",
		"no configmap":     "apiVersion: v1\nkind: Secret\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := updateConfigMap([]byte(input), []byte("new"), configMapOptions{key: "client.jks"}); err == nil {
				t.Fatal("accepted invalid manifest")
			}
		})
	}
	missing := "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: empty\n"
	if _, _, err := updateConfigMap([]byte(missing), nil, configMapOptions{key: "new.bin"}); err == nil {
		t.Fatal("created without --create")
	}
	out, change, err = updateConfigMap([]byte(missing), nil, configMapOptions{key: "new.bin", create: true})
	if err != nil || !change.changed || !strings.Contains(string(out), "new.bin: \"\"") {
		t.Fatalf("--create empty file failed: %v\n%s", err, out)
	}
}

func TestConfigMapCLIWriteModes(t *testing.T) {
	for _, mode := range []string{"in-place", "out", "dry-run", "unchanged", "existing-backup", "existing-out"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			manifest := filepath.Join(dir, "assets.yml")
			file := filepath.Join(dir, "new.jks")
			out := filepath.Join(dir, "updated.yml")
			original := []byte(cmFixture)
			payload := []byte{0, 255, 4, 5}
			if mode == "unchanged" {
				payload = []byte("old")
			}
			for p, data := range map[string][]byte{manifest: original, file: payload} {
				if err := os.WriteFile(p, data, 0640); err != nil {
					t.Fatal(err)
				}
			}
			args := []string{"configmap", "set-binary", "--manifest", manifest, "--key", "client.jks", "--file", file}
			if mode == "out" || mode == "existing-out" {
				args = append(args, "--out", out)
			}
			if mode == "dry-run" {
				args = append(args, "--dry-run", "--out", out)
			}
			if mode == "existing-backup" {
				if err := os.WriteFile(manifest+".bak", []byte("keep backup"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "existing-out" {
				if err := os.WriteFile(out, []byte("keep output"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			var stdout bytes.Buffer
			err := run(args, &stdout, &bytes.Buffer{})
			wantFailure := strings.HasPrefix(mode, "existing-")
			if (err != nil) != wantFailure {
				t.Fatalf("unexpected error: %v", err)
			}
			current, err := os.ReadFile(manifest)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "in-place" {
				backup, err := os.ReadFile(manifest + ".bak")
				if err != nil || !bytes.Equal(backup, original) {
					t.Fatal("backup differs from original")
				}
				if bytes.Equal(current, original) {
					t.Fatal("manifest unchanged")
				}
				info, err := os.Stat(manifest)
				if err != nil || info.Mode().Perm() != 0640 {
					t.Fatal("permissions changed")
				}
			} else if !bytes.Equal(current, original) {
				t.Fatal("unexpected source modification")
			}
			if mode == "out" {
				data, err := os.ReadFile(out)
				if err != nil || bytes.Equal(data, original) {
					t.Fatal("output missing or unchanged")
				}
			}
			if mode == "dry-run" {
				if _, err := os.Stat(out); !os.IsNotExist(err) {
					t.Fatal("dry-run created output")
				}
				if strings.Contains(stdout.String(), base64.StdEncoding.EncodeToString(payload)) {
					t.Fatal("dry-run leaked base64")
				}
			}
			if mode == "existing-backup" {
				data, _ := os.ReadFile(manifest + ".bak")
				if string(data) != "keep backup" {
					t.Fatal("backup overwritten")
				}
			} else if mode != "in-place" {
				if _, err := os.Stat(manifest + ".bak"); !os.IsNotExist(err) {
					t.Fatal("unexpected backup")
				}
			}
			if mode == "existing-out" {
				data, _ := os.ReadFile(out)
				if string(data) != "keep output" {
					t.Fatal("output overwritten")
				}
			}
		})
	}
}

func TestConfigMapSymlinkInPlaceRejected(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "real.yml")
	link := filepath.Join(dir, "link.yml")
	payload := filepath.Join(dir, "new.bin")
	if err := os.WriteFile(source, []byte(cmFixture), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(payload, []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(source, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	args := []string{"configmap", "set-binary", "--manifest", link, "--key", "client.jks", "--file", payload}
	if err := run(args, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("replaced symlink in place")
	}
	original, err := os.ReadFile(source)
	if err != nil || string(original) != cmFixture {
		t.Fatal("modified source through symlink")
	}
	if _, err := os.Stat(link + ".bak"); !os.IsNotExist(err) {
		t.Fatal("created backup despite refusal")
	}
	if err := run(append(args, "--dry-run"), &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatalf("read-only dry-run rejected: %v", err)
	}
}
