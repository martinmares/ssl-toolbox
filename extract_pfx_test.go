package main

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"software.sslmate.com/src/go-pkcs12"
)

func TestExtractPFX(t *testing.T) {
	key, cert, ca := fixture(t)
	for name, encoder := range map[string]*pkcs12.Encoder{"modern": pkcs12.Modern2023, "legacy": pkcs12.LegacyRC2} {
		for _, withChain := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/chain=%t", name, withChain), func(t *testing.T) {
				dir := t.TempDir()
				var chain []*x509.Certificate
				if withChain {
					chain = []*x509.Certificate{ca}
				}
				data, err := encoder.Encode(key, cert, chain, "secret")
				if err != nil {
					t.Fatal(err)
				}
				input := filepath.Join(dir, "client.pfx")
				if err := os.WriteFile(input, data, 0600); err != nil {
					t.Fatal(err)
				}
				passFile := filepath.Join(dir, "password")
				if err := os.WriteFile(passFile, []byte("secret\r\n"), 0600); err != nil {
					t.Fatal(err)
				}
				t.Setenv("EXTRACT_PASSWORD", "secret")
				for _, source := range [][]string{{"--pass-env", "EXTRACT_PASSWORD"}, {"--pass-file", passFile}} {
					out := filepath.Join(dir, source[0])
					args := append([]string{"extract", input, "--out-dir", out}, source...)
					var stdout, stderr bytes.Buffer
					if err := run(args, &stdout, &stderr); err != nil {
						t.Fatal(err)
					}
					for _, suffix := range []string{".key", ".pem", ".chain.pem"} {
						path := filepath.Join(out, "client"+suffix)
						if suffix == ".chain.pem" && !withChain {
							if _, err := os.Stat(path); !os.IsNotExist(err) {
								t.Fatal("created empty chain")
							}
							continue
						}
						got, err := os.ReadFile(path)
						if err != nil {
							t.Fatal(err)
						}
						block, rest := pem.Decode(got)
						if block == nil || len(rest) != 0 || !bytes.HasPrefix(got, []byte("-----BEGIN ")) {
							t.Fatal("output is not a single clean PEM block")
						}
						if suffix == ".key" {
							gotKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
							if err != nil || !key.Equal(gotKey) || block.Type != "PRIVATE KEY" {
								t.Fatal("exported key differs")
							}
						} else {
							want := cert.Raw
							if suffix == ".chain.pem" {
								want = ca.Raw
							}
							if block.Type != "CERTIFICATE" || !bytes.Equal(block.Bytes, want) {
								t.Fatal("exported certificate differs")
							}
						}
						stat, err := os.Stat(path)
						if err != nil || stat.Mode().Perm() != 0600 {
							t.Fatal("output permissions are not 0600")
						}
						if bytes.Contains(stdout.Bytes(), block.Bytes) || bytes.Contains(stdout.Bytes(), got) {
							t.Fatal("private/certificate material printed")
						}
					}
					if stderr.Len() != 0 || strings.Contains(stdout.String(), "secret") {
						t.Fatal("prompt or password leak")
					}
					if err := run(args, &stdout, &stderr); err == nil {
						t.Fatal("overwrote existing outputs")
					}
				}
			})
		}
	}
}

func TestExtractPFXRefusesInvalidInputAndCollisions(t *testing.T) {
	key, cert, _ := fixture(t)
	data, err := pkcs12.Modern2023.Encode(key, cert, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	input := filepath.Join(dir, "client.pfx")
	if err := os.WriteFile(input, data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EXTRACT_WRONG", "wrong")
	for name, flags := range map[string][]string{
		"wrong password":      {"--pass-env", "EXTRACT_WRONG"},
		"missing env":         {"--pass-env", "EXTRACT_MISSING"},
		"bad key entry":       {"--entry", "entry-999"},
		"bad cert entry":      {"--cert-entry", "entry-999"},
		"conflicting sources": {"--pass-env", "EXTRACT_WRONG", "--pass-file", "missing"},
	} {
		out := filepath.Join(dir, name)
		err := run(append([]string{"extract", input, "--out-dir", out}, flags...), &bytes.Buffer{}, &bytes.Buffer{})
		if err == nil {
			t.Fatalf("accepted %s", name)
		}
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Fatalf("created output directory for %s", name)
		}
	}
	// A conflict in the second output must not leave the first (private key).
	out := filepath.Join(dir, "collision")
	if err := os.Mkdir(out, 0700); err != nil {
		t.Fatal(err)
	}
	existing := filepath.Join(out, "client.pem")
	if err := os.Symlink(input, existing); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"extract", input, "--out-dir", out}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("overwrote symlink")
	}
	if _, err := os.Stat(filepath.Join(out, "client.key")); !os.IsNotExist(err) {
		t.Fatal("left a partial export")
	}
	got, err := os.ReadFile(input)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("modified input PFX")
	}
	if err := os.WriteFile(input, []byte("not a PFX"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"extract", input, "--out-dir", filepath.Join(dir, "invalid")}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("accepted invalid PFX")
	}
}

func TestSelectPFXIdentity(t *testing.T) {
	key, cert, ca := fixture(t)
	otherKey, otherCert, _ := fixture(t)
	info := &pkcs12.Inspection{Entries: []pkcs12.InspectionEntry{
		{PrivateKey: key}, {Certificate: cert}, {Certificate: ca}, {PrivateKey: otherKey}, {Certificate: otherCert},
	}}
	if _, _, err := selectPFXIdentity(info, "", ""); err == nil {
		t.Fatal("silently selected one of multiple keys")
	}
	gotKey, gotCert, err := selectPFXIdentity(info, "entry-4", "")
	if err != nil || !otherKey.Equal(gotKey) || gotCert != otherCert {
		t.Fatalf("wrong identity selection: %v", err)
	}
	if _, _, err := selectPFXIdentity(info, "entry-4", "entry-2"); err == nil {
		t.Fatal("accepted mismatched certificate")
	}
	info.Entries = append(info.Entries, pkcs12.InspectionEntry{Certificate: cert})
	if _, _, err := selectPFXIdentity(info, "entry-1", ""); err != nil {
		t.Fatalf("duplicate identical cert is ambiguous: %v", err)
	}
	chain, err := extractPFXChain(cert, info)
	block, rest := pem.Decode(chain)
	if err != nil || block == nil || len(rest) != 0 || !bytes.Equal(block.Bytes, ca.Raw) {
		t.Fatalf("included unrelated certificates or lost CA: %v", err)
	}
	// Renewed certificates may share a public key; require an explicit choice.
	renewed := *cert
	renewed.SerialNumber = big.NewInt(42)
	der, err := x509.CreateCertificate(rand.Reader, &renewed, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	renewedCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	info.Entries = append(info.Entries, pkcs12.InspectionEntry{Certificate: renewedCert})
	if _, _, err := selectPFXIdentity(info, "entry-1", ""); err == nil {
		t.Fatal("silently selected one of multiple matching certificates")
	}
	_, gotCert, err = selectPFXIdentity(info, "entry-1", "entry-7")
	if err != nil || gotCert != renewedCert {
		t.Fatalf("failed explicit certificate selection: %v", err)
	}
}

func TestExtractPFXChainOrderAndAmbiguity(t *testing.T) {
	rootKey, _, _ := fixture(t)
	intermediateKey, _, _ := fixture(t)
	leafKey, leafTemplate, _ := fixture(t)
	makeCert := func(template, parent *x509.Certificate, public any, signer any) *x509.Certificate {
		t.Helper()
		der, err := x509.CreateCertificate(rand.Reader, template, parent, public, signer)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(10), Subject: leafTemplate.Subject,
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		NotBefore: leafTemplate.NotBefore, NotAfter: leafTemplate.NotAfter,
	}
	rootTemplate.Subject.CommonName = "Root"
	root := makeCert(rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	intermediateTemplate := *rootTemplate
	intermediateTemplate.SerialNumber = big.NewInt(11)
	intermediateTemplate.Subject.CommonName = "Intermediate"
	intermediate := makeCert(&intermediateTemplate, root, &intermediateKey.PublicKey, rootKey)
	leaf := makeCert(leafTemplate, intermediate, &leafKey.PublicKey, intermediateKey)
	info := &pkcs12.Inspection{Entries: []pkcs12.InspectionEntry{
		{Certificate: root}, {Certificate: leaf}, {Certificate: intermediate}, {Certificate: root},
	}}
	chain, err := extractPFXChain(leaf, info)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []*x509.Certificate{intermediate, root} {
		block, rest := pem.Decode(chain)
		if block == nil || !bytes.Equal(block.Bytes, expected.Raw) {
			t.Fatal("incorrect chain order or certificate")
		}
		chain = rest
	}
	if len(chain) != 0 {
		t.Fatal("included duplicate root")
	}
	intermediateTemplate.SerialNumber = big.NewInt(12)
	alternative := makeCert(&intermediateTemplate, root, &intermediateKey.PublicKey, rootKey)
	info.Entries = append(info.Entries, pkcs12.InspectionEntry{Certificate: alternative})
	if _, err := extractPFXChain(leaf, info); err == nil {
		t.Fatal("accepted ambiguous issuers")
	}
}
