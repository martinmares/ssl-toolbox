package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestCSRCreateAndInspect(t *testing.T) {
	dir := t.TempDir()
	names := filepath.Join(dir, "dns.txt")
	if err := os.WriteFile(names, []byte("# aliases\r\nserver.example.org\r\nserver # short name\n\nSERVER.EXAMPLE.ORG\n"), 0600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "nested", "certificates")
	var stdout bytes.Buffer
	args := []string{"csr", "create", "--cn", "server.example.org", "--email", "admin@example.org", "--country", "cz", "--province", "Czech Republic", "--locality", "Prague", "--organization", "Příliš žluťoučký kůň", "--organizational-unit", "WEB", "--sans-file", names, "--dns", "*.example.org", "--ip", "192.0.2.10", "--ip", "2001:db8::10", "--ip", "2001:0db8::10", "--out-dir", out, "--name", "server"}
	if err := run(args, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	keyPath, csrPath := filepath.Join(out, "server.key"), filepath.Join(out, "server.csr")
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(keyPath)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("wrong key permissions: %v", err)
		}
	}
	block, _ := pem.Decode(keyData)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatal("expected unencrypted PKCS#8 PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil || key.(*rsa.PrivateKey).N.BitLen() != 4096 {
		t.Fatalf("wrong default key: %v", err)
	}
	csrData, err := os.ReadFile(csrPath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ = pem.Decode(csrData)
	request, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || request.CheckSignature() != nil {
		t.Fatalf("invalid CSR: %v", err)
	}
	if request.SignatureAlgorithm != x509.SHA256WithRSA || request.PublicKey.(*rsa.PublicKey).N.Cmp(key.(*rsa.PrivateKey).N) != 0 {
		t.Fatal("signature or key mismatch")
	}
	if request.Subject.CommonName != "server.example.org" || !reflect.DeepEqual(request.Subject.Country, []string{"CZ"}) || !reflect.DeepEqual(request.Subject.Organization, []string{"Příliš žluťoučký kůň"}) || !reflect.DeepEqual(request.Subject.OrganizationalUnit, []string{"WEB"}) {
		t.Fatalf("wrong subject: %+v", request.Subject)
	}
	emailFound := false
	for _, name := range request.Subject.Names {
		if name.Type.String() == "1.2.840.113549.1.9.1" && name.Value == "admin@example.org" {
			emailFound = true
		}
	}
	if !emailFound || !reflect.DeepEqual(request.DNSNames, []string{"*.example.org", "server.example.org", "server"}) || len(request.IPAddresses) != 2 || len(request.EmailAddresses) != 0 {
		t.Fatalf("wrong requested identities: %+v", request)
	}
	for _, data := range [][]byte{csrData, request.Raw, pem.EncodeToMemory(&pem.Block{Type: "NEW CERTIFICATE REQUEST", Bytes: request.Raw})} {
		r := inspectTestData(t, data, "", "")
		if r.RequestCount != 1 || r.CertificateCount != 0 || !r.Entries[0].Request.SignatureValid || len(r.Entries[0].Request.SAN) != 5 {
			t.Fatalf("bad CSR inspection: %+v", r)
		}
	}
	var printed bytes.Buffer
	if err := run([]string{"inspect", csrPath, "--color", "never"}, &printed, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(printed.String(), "CSR signature: VERIFIED") || strings.Contains(printed.String(), "Expiry:") || strings.Contains(printed.String(), "Certificate dates:") {
		t.Fatalf("misleading CSR output: %s", &printed)
	}
	if err := run([]string{"inspect", csrPath, "--pdf", filepath.Join(dir, "request.pdf")}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if err := run(args, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("overwrote output")
	}
	if data, _ := os.ReadFile(keyPath); !bytes.Equal(data, keyData) {
		t.Fatal("private key changed on retry")
	}
	if openssl, err := exec.LookPath("openssl"); err == nil {
		if output, err := exec.Command(openssl, "req", "-in", csrPath, "-verify", "-noout").CombinedOutput(); err != nil {
			t.Fatalf("OpenSSL rejected CSR: %v %s", err, output)
		}
	}
}

func TestCSRReuseKeysAndRejectInvalidInput(t *testing.T) {
	dir := t.TempDir()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyDER := x509.MarshalPKCS1PrivateKey(key)
	encrypted, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", keyDER, []byte("key-secret"), x509.PEMCipherAES256)
	if err != nil {
		t.Fatal(err)
	}
	password := filepath.Join(dir, "password")
	if err := os.WriteFile(password, []byte("key-secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CSR_TEST_PASSWORD", "key-secret")
	for _, tt := range []struct {
		name string
		data []byte
		pass []string
	}{
		{"der", keyDER, nil},
		{"pem", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER}), nil},
		{"encrypted-env", pem.EncodeToMemory(encrypted), []string{"--key-pass-env", "CSR_TEST_PASSWORD"}},
		{"encrypted-file", pem.EncodeToMemory(encrypted), []string{"--key-pass-file", password}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(dir, tt.name+".key")
			if err := os.WriteFile(path, tt.data, 0600); err != nil {
				t.Fatal(err)
			}
			out := filepath.Join(dir, tt.name)
			args := []string{"csr", "create", "--cn", "client.example.org", "--dns", "client.example.org", "--out-dir", out, "--key", path}
			if err := run(append(args, tt.pass...), &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
				t.Fatal(err)
			}
			if data, _ := os.ReadFile(path); !bytes.Equal(data, tt.data) {
				t.Fatal("existing key changed")
			}
			if _, err := os.Stat(filepath.Join(out, "client.example.org.key")); !os.IsNotExist(err) {
				t.Fatal("existing key copied to output")
			}
			data, err := os.ReadFile(filepath.Join(out, "client.example.org.csr"))
			if err != nil {
				t.Fatal(err)
			}
			block, _ := pem.Decode(data)
			request, err := x509.ParseCertificateRequest(block.Bytes)
			if err != nil || request.CheckSignature() != nil || request.PublicKey.(*rsa.PublicKey).N.Cmp(key.N) != 0 {
				t.Fatal("reused key mismatch")
			}
		})
	}
	for _, flags := range [][]string{
		{"--name", "../escape"}, {"--name", `a\b`}, {"--cn", ""}, {"--cn", "*.example.org"},
		{"--country", "CZE"}, {"--email", "not-an-email"}, {"--bits", "1024"},
		{"--dns", "192.0.2.10"}, {"--dns", "a.*.example.org"}, {"--dns", "a..example.org"},
		{"--dns", "bad_name"}, {"--ip", "999.0.0.1"}, {"--sans-file", filepath.Join(dir, "missing")},
		{"--key", filepath.Join(dir, "pem.key"), "--bits", "2048"}, {"--key-pass-env", "CSR_TEST_PASSWORD"},
		{"--key", filepath.Join(dir, "encrypted-env.key"), "--key-pass-env", "MISSING_CSR_PASSWORD"},
	} {
		out := filepath.Join(dir, "invalid")
		args := append([]string{"csr", "create", "--cn", "client.example.org", "--out-dir", out}, flags...)
		if err := run(args, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
			t.Fatalf("accepted invalid options: %v", flags)
		}
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Fatal("wrote output for invalid request")
		}
	}
}

func TestInspectTamperedCSR(t *testing.T) {
	key, _, _ := fixture(t)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	der[len(der)-1] ^= 1
	report := inspectTestData(t, der, "", "")
	if report.Entries[0].Request.SignatureValid || report.Entries[0].Request.SignatureError == "" {
		t.Fatal("accepted tampered CSR signature")
	}
	var output bytes.Buffer
	if err := printInspection(&output, report); err != nil || !strings.Contains(output.String(), "CSR signature: FAILED:") {
		t.Fatal("missing invalid signature warning")
	}
}

func TestCSRReuseEncryptedPKCS8(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("OpenSSL unavailable")
	}
	dir := t.TempDir()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("CSR_PKCS8_PASSWORD", "pkcs8-secret")
	cmd := exec.Command(openssl, "pkcs8", "-topk8", "-inform", "DER", "-outform", "PEM", "-v2", "aes-256-cbc", "-passout", "env:CSR_PKCS8_PASSWORD")
	cmd.Stdin = bytes.NewReader(x509.MarshalPKCS1PrivateKey(key))
	data, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "encrypted.key")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"csr", "create", "--cn", "client.example.org", "--key", path, "--key-pass-env", "CSR_PKCS8_PASSWORD", "--out-dir", filepath.Join(dir, "requests")}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	wrong, _, _ := fixture(t)
	der, err := x509.MarshalPKCS8PrivateKey(wrong)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readCSRKey(path, &inspectPassword{}); err == nil {
		t.Fatal("CSR accepted non-RSA key")
	}
}
