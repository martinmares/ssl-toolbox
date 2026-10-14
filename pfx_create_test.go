package main

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

func TestCSRToIssuedCertificateToPFX(t *testing.T) {
	dir := t.TempDir()
	if err := run([]string{"csr", "create", "--cn", "server.example.org", "--dns", "server.example.org", "--ip", "192.0.2.10", "--bits", "2048", "--out-dir", dir, "--name", "server"}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	requestPEM, err := os.ReadFile(filepath.Join(dir, "server.csr"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(requestPEM)
	request, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate the CA response; production commands only create CSRs and package
	// certificates issued by an external CA.
	caKey, _, _ := fixture(t)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(10), Subject: pkix.Name{CommonName: "Example CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(11), Subject: request.Subject, DNSNames: request.DNSNames, IPAddresses: request.IPAddresses, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, request.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(dir, "chain.pem")
	if err := os.WriteFile(caFile, bytes.Repeat(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 2), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PFX_CREATE_PASSWORD", "new-pfx-secret")
	passwordFile := filepath.Join(dir, "password")
	if err := os.WriteFile(passwordFile, []byte("new-pfx-secret\r\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"pem", "der"} {
		certFile := filepath.Join(dir, "issued."+format)
		data := leafDER
		passArgs := []string{"--out-pass-env", "PFX_CREATE_PASSWORD"}
		if format == "pem" {
			data = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
			passArgs = []string{"--out-pass-file", passwordFile}
		}
		if err := os.WriteFile(certFile, data, 0600); err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(dir, format+".pfx")
		args := append([]string{"pfx", "create", "--key", filepath.Join(dir, "server.key"), "--cert", certFile, "--chain", caFile, "--out", out}, passArgs...)
		if err := run(args, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
		pfx, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		_, cert, chain, err := pkcs12.DecodeChain(pfx, "new-pfx-secret")
		if err != nil || !bytes.Equal(cert.Raw, leafDER) || len(chain) != 1 || !bytes.Equal(chain[0].Raw, caDER) {
			t.Fatalf("bad PFX identity: %v", err)
		}
		if _, _, _, err := pkcs12.DecodeChain(pfx, "wrong"); err == nil {
			t.Fatal("accepted wrong PFX password")
		}
		r := inspectTestData(t, pfx, "new-pfx-secret", "")
		if r.PrivateKeyCount != 1 || r.CertificateCount != 2 || r.MAC.Algorithm != "SHA-256" || len(r.Entries[0].Matches) == 0 {
			t.Fatalf("incorrect modern identity: %+v", r)
		}
		if err := run(args, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
			t.Fatal("overwrote PFX")
		}
		if openssl, err := exec.LookPath("openssl"); err == nil {
			if output, err := exec.Command(openssl, "pkcs12", "-in", out, "-passin", "env:PFX_CREATE_PASSWORD", "-info", "-noout").CombinedOutput(); err != nil {
				t.Fatalf("OpenSSL rejected modern PFX: %v %s", err, output)
			}
		}
	}
	_, wrongCert, unrelatedCA := fixture(t)
	wrongCertFile := filepath.Join(dir, "wrong.pem")
	if err := os.WriteFile(wrongCertFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: wrongCert.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	wrongCAFile := filepath.Join(dir, "unrelated.pem")
	if err := os.WriteFile(wrongCAFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: unrelatedCA.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	for _, flags := range [][]string{
		{"--cert", wrongCertFile}, {"--chain", wrongCAFile}, {"--chain", filepath.Join(dir, "issued.pem")},
		{"--out-pass-env", "MISSING_PFX_PASSWORD"}, {"--cert", filepath.Join(dir, "server.csr")},
	} {
		out := filepath.Join(dir, "invalid.pfx")
		args := append([]string{"pfx", "create", "--key", filepath.Join(dir, "server.key"), "--cert", filepath.Join(dir, "issued.pem"), "--out", out, "--out-pass-env", "PFX_CREATE_PASSWORD"}, flags...)
		if err := run(args, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
			t.Fatalf("accepted invalid PFX request: %v", flags)
		}
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Fatal("created invalid PFX")
		}
	}
}

func TestPFXCreateExistingECIdentity(t *testing.T) {
	key, cert, ca := fixture(t)
	dir := t.TempDir()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	for name, block := range map[string]*pem.Block{
		"key.pem":  {Type: "EC PRIVATE KEY", Bytes: der},
		"cert.pem": {Type: "CERTIFICATE", Bytes: cert.Raw},
		"ca.pem":   {Type: "CERTIFICATE", Bytes: ca.Raw},
	} {
		if err := os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(block), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PFX_EC_PASSWORD", "ec-secret")
	if err := run([]string{"pfx", "create", "--key", filepath.Join(dir, "key.pem"), "--cert", filepath.Join(dir, "cert.pem"), "--chain", filepath.Join(dir, "ca.pem"), "--out", filepath.Join(dir, "identity.pfx"), "--out-pass-env", "PFX_EC_PASSWORD"}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
}
