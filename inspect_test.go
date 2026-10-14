package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
	"software.sslmate.com/src/go-pkcs12"
)

func inspectTestData(t *testing.T, data []byte, pw, keyPW string) *inspectionReport {
	t.Helper()
	t.Setenv("INSPECT_TEST_PASS", pw)
	t.Setenv("INSPECT_TEST_KEY", keyPW)
	r, err := inspectContents(data, &inspectPassword{env: "INSPECT_TEST_PASS"}, &inspectPassword{env: "INSPECT_TEST_KEY"})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestInspectPFXProtection(t *testing.T) {
	key, cert, ca := fixture(t)
	for name, enc := range map[string]*pkcs12.Encoder{"legacy": pkcs12.LegacyRC2, "modern": pkcs12.Modern2023} {
		t.Run(name, func(t *testing.T) {
			data, err := enc.Encode(key, cert, []*x509.Certificate{ca}, "secret")
			if err != nil {
				t.Fatal(err)
			}
			r := inspectTestData(t, data, "secret", "")
			if r.Format != "PKCS#12" || r.CertificateCount != 2 || r.PrivateKeyCount != 1 || r.Integrity != "verified" || r.MAC == nil || len(r.Encryption) != 1 {
				t.Fatalf("wrong report: %+v", r)
			}
			found := false
			for _, e := range r.Entries {
				if e.Type == "private key" {
					found = len(e.Matches) == 1 && e.Protection != nil
				}
			}
			if !found {
				t.Fatal("missing key/cert match or protection")
			}
			t.Setenv("INSPECT_TEST_PASS", "wrong")
			if _, err := inspectContents(data, &inspectPassword{env: "INSPECT_TEST_PASS"}, &inspectPassword{}); err == nil {
				t.Fatal("accepted wrong password")
			}
		})
	}
	data, err := pkcs12.Modern2023.Encode(key, cert, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inspectContents(data, &inspectPassword{}, &inspectPassword{}); err != nil {
		t.Fatalf("empty password prompted: %v", err)
	}
}

func TestInspectMultipleJKSIdentities(t *testing.T) {
	ks := keystore.New(keystore.WithCaseExactAliases())
	for _, alias := range []string{"Alpha", "Beta"} {
		key, cert, ca := fixture(t)
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		entry := keystore.PrivateKeyEntry{CreationTime: time.Now(), PrivateKey: der, CertificateChain: []keystore.Certificate{{Type: "X.509", Content: cert.Raw}, {Type: "X.509", Content: ca.Raw}}}
		if err := ks.SetPrivateKeyEntry(alias, entry, []byte("key-secret")); err != nil {
			t.Fatal(err)
		}
	}
	_, _, ca := fixture(t)
	if err := ks.SetTrustedCertificateEntry("CA", keystore.TrustedCertificateEntry{CreationTime: time.Now(), Certificate: keystore.Certificate{Type: "X.509", Content: ca.Raw}}); err != nil {
		t.Fatal(err)
	}
	var data bytes.Buffer
	if err := ks.Store(&data, []byte("store-secret")); err != nil {
		t.Fatal(err)
	}
	r := inspectTestData(t, data.Bytes(), "store-secret", "key-secret")
	dir := t.TempDir()
	storeFile, keyFile := filepath.Join(dir, "store-pass"), filepath.Join(dir, "key-pass")
	if err := os.WriteFile(storeFile, []byte("store-secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, []byte("key-secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectContents(data.Bytes(), &inspectPassword{file: storeFile}, &inspectPassword{file: keyFile}); err != nil {
		t.Fatal(err)
	}

	if r.Format != "JKS" || r.PrivateKeyCount != 2 || r.CertificateCount != 5 || r.EntryCount != 7 {
		t.Fatalf("missing entries: %+v", r)
	}
	for _, e := range r.Entries {
		if e.Type == "private key" && (len(e.Matches) != 1 || e.Created == nil) {
			t.Fatal("missing key match/date")
		}
	}
	t.Setenv("INSPECT_TEST_KEY", "wrong")
	if _, err := inspectContents(data.Bytes(), &inspectPassword{env: "INSPECT_TEST_PASS"}, &inspectPassword{env: "INSPECT_TEST_KEY"}); err == nil {
		t.Fatal("accepted wrong key password")
	}
}

func TestInspectPEMAndDER(t *testing.T) {
	key, cert, ca := fixture(t)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	var bundle []byte
	for _, block := range []*pem.Block{{Type: "CERTIFICATE", Bytes: cert.Raw}, {Type: "CERTIFICATE", Bytes: ca.Raw}, {Type: "PRIVATE KEY", Bytes: keyDER}, {Type: "PUBLIC KEY", Bytes: publicDER}} {
		bundle = append(bundle, pem.EncodeToMemory(block)...)
	}
	r := inspectTestData(t, bundle, "", "")
	if r.CertificateCount != 2 || r.PrivateKeyCount != 1 || r.PublicKeyCount != 1 {
		t.Fatal("missing PEM objects")
	}
	for _, data := range [][]byte{cert.Raw, keyDER, publicDER, append(append([]byte{}, cert.Raw...), ca.Raw...)} {
		if r := inspectTestData(t, data, "", ""); r.Format != "DER" {
			t.Fatal("wrong DER format")
		}
	}
	encrypted, err := x509.EncryptPEMBlock(rand.Reader, "EC PRIVATE KEY", mustECKey(t, key), []byte("pem-secret"), x509.PEMCipherAES256)
	if err != nil {
		t.Fatal(err)
	}
	r = inspectTestData(t, pem.EncodeToMemory(encrypted), "pem-secret", "")
	if r.PrivateKeyCount != 1 || r.Entries[0].Protection.Cipher != "AES-256-CBC" {
		t.Fatal("encrypted PEM not inspected")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "misleading.jks")
	if err := os.WriteFile(path, bundle, 0600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := run([]string{"inspect", path, "--json"}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var parsed inspectionReport
	if err := json.Unmarshal(output.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Format != "PEM" || parsed.File != path {
		t.Fatal("used extension")
	}
	if bytes.Contains(output.Bytes(), []byte("PRIVATE KEY")) || bytes.Contains(output.Bytes(), []byte(key.D.Text(16))) {
		t.Fatal("private material printed")
	}
	if err := printInspection(failingWriter{}, r); err == nil {
		t.Fatal("ignored write error")
	}
	for _, data := range [][]byte{[]byte("garbage"), append(bundle, []byte("garbage")...), []byte("-----BEGIN UNKNOWN-----\nYQ==\n-----END UNKNOWN-----\n"), bundle[:len(bundle)-20]} {
		if _, err := inspectContents(data, &inspectPassword{}, &inspectPassword{}); err == nil {
			t.Fatal("accepted incomplete content")
		}
	}
	if err := run([]string{"inspect", path}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Subject:") {
		t.Fatal("missing details")
	}
}

func mustECKey(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestInspectOpenSSLPEMMetadata(t *testing.T) {
	key, cert, ca := fixture(t)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	metadata := "Bag Attributes\n    localKeyID: 01 02 03\n    friendlyName: test certificate\nsubject=CN=test\nissuer=CN=test CA\n"
	bundle := metadata + string(certPEM) + "Bag Attributes: <No Attributes>\nsubject=CN=test CA\nissuer=CN=test CA\n" + string(caPEM) +
		"Bag Attributes\n    friendlyName: test key\nKey Attributes\n    X509v3 Key Usage: 10\n" + string(keyPEM)
	for name, data := range map[string]string{
		"certificate":   metadata + string(certPEM),
		"bundle":        bundle,
		"CRLF":          strings.ReplaceAll(bundle, "\n", "\r\n"),
		"BOM":           "\xef\xbb\xbf\n  \n" + bundle,
		"no attributes": "Bag Attributes: <No Attributes>\nKey Attributes: <No Attributes>\n" + string(keyPEM),
	} {
		t.Run(name, func(t *testing.T) {
			r := inspectTestData(t, []byte(data), "", "")
			if r.Format != "PEM" {
				t.Fatalf("wrong format: %s", r.Format)
			}
			switch name {
			case "certificate":
				if r.CertificateCount != 1 || r.Entries[0].Certificate.Subject != cert.Subject.String() {
					t.Fatal("missing certificate")
				}
			case "no attributes":
				if r.PrivateKeyCount != 1 {
					t.Fatal("missing private key")
				}
			default:
				if r.CertificateCount != 2 || r.PrivateKeyCount != 1 || r.EntryCount != 3 || len(r.Entries[2].Matches) != 1 {
					t.Fatalf("missing bundle entries or key match: %+v", r)
				}
			}
		})
	}
	for name, data := range map[string]string{
		"metadata only":               metadata,
		"unknown preamble":            "garbage\n" + string(certPEM),
		"unknown metadata":            "Bag Attributes\n    garbage\n" + string(certPEM),
		"unknown text between blocks": metadata + string(certPEM) + "garbage\n" + string(caPEM),
		"malformed block":             metadata + string(certPEM[:len(certPEM)-20]),
		"malformed later block":       metadata + string(certPEM) + metadata + string(caPEM[:len(caPEM)-20]),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := inspectContents([]byte(data), &inspectPassword{}, &inspectPassword{}); err == nil {
				t.Fatal("accepted incomplete or unsupported content")
			}
		})
	}
}

func TestInspectEncryptedPKCS8Interoperability(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("OpenSSL unavailable")
	}
	key, _, _ := fixture(t)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("INSPECT_PKCS8_PASSWORD", "pkcs8-secret")
	cmd := exec.Command(openssl, "pkcs8", "-topk8", "-inform", "DER", "-outform", "DER", "-v2", "aes-256-cbc", "-passout", "env:INSPECT_PKCS8_PASSWORD")
	cmd.Stdin = bytes.NewReader(der)
	var diagnostics bytes.Buffer
	cmd.Stderr = &diagnostics
	encrypted, err := cmd.Output()
	if err != nil {
		t.Fatalf("generate encrypted fixture: %v %s", err, &diagnostics)
	}
	for _, data := range [][]byte{encrypted, pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: encrypted})} {
		r := inspectTestData(t, data, "pkcs8-secret", "")
		if r.PrivateKeyCount != 1 || r.Entries[0].Protection == nil || r.Entries[0].Protection.Cipher != "AES-256-CBC" {
			t.Fatal("missing encryption metadata")
		}
		expected, err := keyDetails(&key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		if r.Entries[0].PublicKey.SHA256 != expected.SHA256 {
			t.Fatal("key changed")
		}
		t.Setenv("INSPECT_TEST_PASS", "wrong")
		if _, err := inspectContents(data, &inspectPassword{env: "INSPECT_TEST_PASS"}, &inspectPassword{}); err == nil {
			t.Fatal("accepted wrong password")
		}
	}
}
