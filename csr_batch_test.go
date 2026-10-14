package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeBatchConfig(t *testing.T, dir, text string) string {
	t.Helper()
	path := filepath.Join(dir, "requests.yaml")
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCSRBatchDefaultsOverridesAndDryRun(t *testing.T) {
	dir := t.TempDir()
	path := writeBatchConfig(t, dir, `defaults:
  rsaBits: 2048
  subject:
    country: cz
    organization: Example
    organizationalUnit: WEB
requests:
  - name: frontend
    subject:
      commonName: frontend.example.org
    san:
      dns: [frontend.example.org, frontend]
      ip: [192.0.2.10]
  - name: wildcard
    rsaBits: 3072
    subject:
      commonName: "*.example.org"
      organization: Other
      organizationalUnit: ""
    san:
      dns: ["*.example.org", example.org]
      ip: ["2001:db8::10"]
`)
	out := filepath.Join(dir, "certificates")
	var preview bytes.Buffer
	if err := run([]string{"csr", "batch", "--config", path, "--out-dir", out, "--dry-run"}, &preview, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"[frontend]", "[wildcard]", "RSA 2048 bits", "RSA 3072 bits", "DNS:frontend", "IP:192.0.2.10", "IP:2001:db8::10", "frontend.key", "wildcard.csr", "no files written"} {
		if !strings.Contains(preview.String(), want) {
			t.Fatalf("missing %q in plan: %s", want, &preview)
		}
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("dry-run created an output directory")
	}
	plans, err := prepareCSRBatch(path, out, &bytes.Buffer{})
	if err != nil || plans[0].key != nil || plans[1].key != nil {
		t.Fatalf("preflight generated private keys: %v", err)
	}
	var output bytes.Buffer
	if err := run([]string{"csr", "batch", "--config", path, "--out-dir", out}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Completed 2 CSR requests: frontend, wildcard") {
		t.Fatal("missing completion summary")
	}
	for _, name := range []string{"frontend", "wildcard"} {
		data, err := os.ReadFile(filepath.Join(out, name+".csr"))
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(data)
		request, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil || request.CheckSignature() != nil {
			t.Fatalf("invalid request %s: %v", name, err)
		}
		if request.Subject.Country[0] != "CZ" || len(request.IPAddresses) != 1 {
			t.Fatal("defaults or SANs missing")
		}
		if name == "frontend" && (request.Subject.Organization[0] != "Example" || request.Subject.OrganizationalUnit[0] != "WEB" || request.PublicKey.(*rsa.PublicKey).N.BitLen() != 2048) {
			t.Fatal("inherited defaults incorrect")
		}
		if name == "wildcard" && (request.Subject.Organization[0] != "Other" || len(request.Subject.OrganizationalUnit) != 0 || request.PublicKey.(*rsa.PublicKey).N.BitLen() != 3072) {
			t.Fatal("per-request overrides incorrect")
		}
	}
}

func TestCSRBatchRepositoryExample(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out")
	plans, err := prepareCSRBatch("examples/csr-batch.yaml", out, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if len(plans) != 3 || plans[0].options.bits != 4096 || plans[2].options.cn != "*.example.org" {
		t.Fatal("repository YAML example does not match the documented batch")
	}
	var preview bytes.Buffer
	if err := printCSRBatchPlan(plans, &preview); err != nil || !strings.Contains(preview.String(), "Subject emailAddress: admin@example.org") {
		t.Fatal("emailAddress is not readable in the plan")
	}
	if err := printCSRBatchPlan(plans, failingWriter{}); err == nil {
		t.Fatal("ignored dry-run output failure")
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("example preview wrote output files")
	}
}

func TestCSRBatchValidatesEntireBatchBeforeWriting(t *testing.T) {
	valid := "requests:\n  - name: first\n    subject: {commonName: first.example.org}\n"
	for _, second := range []string{
		"  - name: bad\n    subject: {commonName: second.example.org}\n    san: {ip: [invalid]}\n",
		"  - name: bad\n    subject: {commonName: second.example.org}\n    key: {file: missing.key}\n",
		"  - name: FIRST\n    subject: {commonName: second.example.org}\n",
		"  - subject: {commonName: second.example.org}\n",
		"  - name: bad\n    subject: {}\n",
		"  - name: ../outside\n    subject: {commonName: second.example.org}\n",
	} {
		dir := t.TempDir()
		path := writeBatchConfig(t, dir, valid+second)
		out := filepath.Join(dir, "certificates")
		if err := run([]string{"csr", "batch", "--config", path, "--out-dir", out}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
			t.Fatalf("accepted invalid last request: %s", second)
		}
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Fatal("wrote earlier requests before validating last request")
		}
	}
	dir := t.TempDir()
	path := writeBatchConfig(t, dir, valid+"  - name: second\n    subject: {commonName: second.example.org}\n")
	out := filepath.Join(dir, "certificates")
	if err := os.Mkdir(out, 0700); err != nil {
		t.Fatal(err)
	}
	existing := filepath.Join(out, "second.key")
	if err := os.WriteFile(existing, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareCSRBatch(path, out, &bytes.Buffer{}); err == nil {
		t.Fatal("accepted a later output collision")
	}
	files, _ := os.ReadDir(out)
	if len(files) != 1 || files[0].Name() != "second.key" {
		t.Fatal("wrote first request despite second request collision")
	}
}

func TestCSRBatchStrictYAML(t *testing.T) {
	for _, config := range []string{
		"requests: []\n", "requests: null\n",
		"requests:\n  - name: x\n    subject: {commonName: x}\n    typo: true\n",
		"requests:\n  - name: x\n    name: y\n    subject: {commonName: x}\n",
		"defaults: {subject: {commonName: x}}\nrequests: [{name: x, subject: {commonName: x}}]\n",
		"defaults: {rsaBits: 1024}\nrequests: [{name: x, subject: {commonName: x}}]\n",
		"defaults: {subject: {organizaton: Example}}\nrequests: [{name: x, subject: {commonName: x}}]\n",
		"requests: [{name: x, subject: {commonName: x}}]\n---\nrequests: []\n",
		"requests:\n  - &r {name: x, subject: {commonName: x}}\n  - *r\n",
		"requests: [{name: x, subject: {commonName: x}, key: {file: a, password: secret}}]\n",
		"requests: [{name: x, subject: {commonName: x}, key: {file: a, passwordEnv: E, passwordFile: f}}]\n",
		"requests: [{name: x, subject: {commonName: x}, rsaBits: 2048, key: {file: a}}]\n",
	} {
		dir := t.TempDir()
		path := writeBatchConfig(t, dir, config)
		if _, err := prepareCSRBatch(path, filepath.Join(dir, "out"), &bytes.Buffer{}); err == nil {
			t.Fatalf("accepted malformed config: %s", config)
		}
	}
}

func TestCSRBatchExistingKeyPathsAndPasswords(t *testing.T) {
	dir := t.TempDir()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	block, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key), []byte("batch-secret"), x509.PEMCipherAES256)
	if err != nil {
		t.Fatal(err)
	}
	keyBytes := pem.EncodeToMemory(block)
	if err := os.WriteFile(filepath.Join(dir, "existing.key"), keyBytes, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "password"), []byte("batch-secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BATCH_KEY_PASSWORD", "batch-secret")
	for _, source := range []string{"passwordEnv: BATCH_KEY_PASSWORD", "passwordFile: password"} {
		path := writeBatchConfig(t, dir, "requests:\n  - name: reused\n    subject: {commonName: reused.example.org}\n    key:\n      file: existing.key\n      "+source+"\n")
		out := filepath.Join(t.TempDir(), "out")
		var preview bytes.Buffer
		if err := run([]string{"csr", "batch", "--config", path, "--out-dir", out, "--dry-run"}, &preview, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(preview.String(), "batch-secret") || !strings.Contains(preview.String(), "RSA 2048 bits; validated") {
			t.Fatal("password leak or key not validated")
		}
		if err := run([]string{"csr", "batch", "--config", path, "--out-dir", out}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
		files, _ := os.ReadDir(out)
		if len(files) != 1 || files[0].Name() != "reused.csr" {
			t.Fatal("existing key was copied")
		}
		data, _ := os.ReadFile(filepath.Join(out, "reused.csr"))
		block, _ := pem.Decode(data)
		request, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil || request.PublicKey.(*rsa.PublicKey).N.Cmp(key.N) != 0 {
			t.Fatal("request does not use the existing key")
		}
	}
	data, _ := os.ReadFile(filepath.Join(dir, "existing.key"))
	if !bytes.Equal(data, keyBytes) {
		t.Fatal("original key changed")
	}
}

type batchCollisionWriter struct {
	path string
}

func (w *batchCollisionWriter) Write(data []byte) (int, error) {
	if strings.Contains(string(data), "first.csr") {
		if err := os.WriteFile(w.path, []byte("created concurrently"), 0600); err != nil {
			return 0, err
		}
	}
	return len(data), nil
}

func TestCSRBatchReportsPartialProgressAndKeepsExistingFiles(t *testing.T) {
	dir := t.TempDir()
	path := writeBatchConfig(t, dir, "defaults: {rsaBits: 2048}\nrequests:\n  - name: first\n    subject: {commonName: first.example.org}\n  - name: second\n    subject: {commonName: second.example.org}\n  - name: third\n    subject: {commonName: third.example.org}\n")
	out := filepath.Join(dir, "out")
	err := run([]string{"csr", "batch", "--config", path, "--out-dir", out}, &batchCollisionWriter{path: filepath.Join(out, "second.csr")}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), `request "second" failed`) || !strings.Contains(err.Error(), "completed requests: [first]") {
		t.Fatalf("partial progress not reported: %v", err)
	}
	for _, name := range []string{"first.key", "first.csr", "second.csr"} {
		if _, err := os.Stat(filepath.Join(out, name)); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"second.key", "third.key", "third.csr"} {
		if _, err := os.Stat(filepath.Join(out, name)); !os.IsNotExist(err) {
			t.Fatalf("unexpected output %s", name)
		}
	}
	data, _ := os.ReadFile(filepath.Join(out, "second.csr"))
	if string(data) != "created concurrently" {
		t.Fatal("overwrote a concurrently created file")
	}
}
