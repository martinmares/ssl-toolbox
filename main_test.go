package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
	"software.sslmate.com/src/go-pkcs12"
)

func fixture(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate, *x509.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Kafka client"},
		NotBefore: ca.NotBefore, NotAfter: ca.NotAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert, ca
}

func TestJKSConversion(t *testing.T) {
	key, cert, ca := fixture(t)
	pfx, err := pkcs12.LegacyRC2.Encode(key, cert, []*x509.Certificate{ca}, "old password")
	if err != nil {
		t.Fatal(err)
	}
	jks, err := convert(pfx, "old password", "new password", "jks", "Kafka")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(jks, []byte{0xfe, 0xed, 0xfe, 0xed}) {
		t.Fatal("output is not a real JKS")
	}
	ks := keystore.New()
	if err := ks.Load(bytes.NewReader(jks), []byte("new password")); err != nil {
		t.Fatal(err)
	}
	entry, err := ks.GetPrivateKeyEntry("kafka", []byte("new password"))
	if err != nil {
		t.Fatal(err)
	}
	gotKey, err := x509.ParsePKCS8PrivateKey(entry.PrivateKey)
	if err != nil || !key.Equal(gotKey) {
		t.Fatalf("private key changed: %v", err)
	}
	if len(entry.CertificateChain) != 2 || !bytes.Equal(entry.CertificateChain[0].Content, cert.Raw) || !bytes.Equal(entry.CertificateChain[1].Content, ca.Raw) {
		t.Fatal("certificate chain changed")
	}
	if err := keystore.New().Load(bytes.NewReader(jks), []byte("wrong password")); err == nil {
		t.Fatal("accepted wrong store password")
	}
	if _, err := ks.GetPrivateKeyEntry("kafka", []byte("wrong password")); err == nil {
		t.Fatal("accepted wrong key password")
	}
	t.Run("CLI", func(t *testing.T) {
		dir := t.TempDir()
		in, out := filepath.Join(dir, "old.pfx"), filepath.Join(dir, "client.jks")
		if err := os.WriteFile(in, pfx, 0600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("TEST_OLD_PASSWORD", "old password")
		t.Setenv("TEST_NEW_PASSWORD", "new password")
		args := []string{"--in", in, "--out", out, "--format", "jks", "--alias", "Kafka", "--in-pass-env", "TEST_OLD_PASSWORD", "--out-pass-env", "TEST_NEW_PASSWORD"}
		if err := run(append([]string{"convert"}, args...), &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		loaded := keystore.New()
		if err := loaded.Load(bytes.NewReader(data), []byte("new password")); err != nil {
			t.Fatal(err)
		}
		if _, err := loaded.GetPrivateKeyEntry("kafka", []byte("new password")); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("keytool", func(t *testing.T) {
		keytool, err := exec.LookPath("keytool")
		if err != nil {
			t.Skip("keytool unavailable")
		}
		dir := t.TempDir()
		in, out := filepath.Join(dir, "client.jks"), filepath.Join(dir, "java.pfx")
		if err := os.WriteFile(in, jks, 0600); err != nil {
			t.Fatal(err)
		}
		// Import exercises both Java's JKS reader and private key decryption.
		cmd := exec.Command(keytool, "-importkeystore", "-srckeystore", in, "-srcstoretype", "JKS",
			"-srcstorepass:env", "TEST_JKS_PASSWORD", "-srckeypass:env", "TEST_JKS_PASSWORD", "-srcalias", "kafka",
			"-destkeystore", out, "-deststoretype", "PKCS12", "-deststorepass:env", "TEST_JKS_PASSWORD", "-noprompt")
		cmd.Env = append(os.Environ(), "TEST_JKS_PASSWORD=new password")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("Java could not import JKS key: %v\n%s", err, output)
		}
		data, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		gotKey, gotCert, gotChain, err := pkcs12.DecodeChain(data, "new password")
		if err != nil || !key.Equal(gotKey) || !cert.Equal(gotCert) || len(gotChain) != 1 || !ca.Equal(gotChain[0]) {
			t.Fatalf("Java import changed identity or chain: %v", err)
		}
	})
}

func TestCobraCLI(t *testing.T) {
	for _, args := range [][]string{nil, {"--help"}, {"-h"}} {
		var stdout, stderr bytes.Buffer
		if err := run(args, &stdout, &stderr); err != nil {
			t.Fatal(err)
		}
		for _, command := range []string{"convert", "truststore", "configmap", "examples", "inspect"} {
			if !strings.Contains(stdout.String(), command) {
				t.Fatalf("missing %s in root help", command)
			}
		}
	}
	for _, args := range [][]string{{"convert", "--help"}, {"truststore", "--help"}, {"configmap", "set-binary", "--help"}, {"examples", "--help"}} {
		if err := run(args, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{{"convert"}, {"convert", "--in", "x"}, {"--unknown"}, {"unexpected"}, {"convert", "--in", "x", "--out", "y", "--format", "bad"}, {"truststore", "--out", "x"}, {"truststore", "--in", "x", "--out", "y", "--add-ca", "root.pem"}, {"configmap", "set-binary"}} {
		if err := run(args, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
			t.Fatalf("accepted invalid args %v", args)
		}
	}
	args := []string{"convert", "-in", "-out", "--alias", "-in", "-out=result.pfx", "--", "-format"}
	want := []string{"convert", "--in", "-out", "--alias", "-in", "--out=result.pfx", "--", "-format"}
	if got := legacyArgs(args); !reflect.DeepEqual(got, want) {
		t.Fatalf("argument values corrupted: %v", got)
	}
}

func TestLegacyConversion(t *testing.T) {
	key, cert, ca := fixture(t)
	for _, oldPassword := range []string{"old password", ""} {
		t.Run(oldPassword, func(t *testing.T) {
			legacy, err := pkcs12.LegacyRC2.Encode(key, cert, []*x509.Certificate{ca}, oldPassword)
			if err != nil {
				t.Fatal(err)
			}
			modern, err := repack(legacy, oldPassword, "new password")
			if err != nil {
				t.Fatal(err)
			}
			gotKey, gotCert, gotChain, err := pkcs12.DecodeChain(modern, "new password")
			if err != nil {
				t.Fatal(err)
			}
			if !key.Equal(gotKey) || !cert.Equal(gotCert) || len(gotChain) != 1 || !ca.Equal(gotChain[0]) {
				t.Fatal("private key, client certificate or chain changed")
			}
			if _, err := repack(legacy, "wrong", "new password"); err == nil {
				t.Fatal("accepted wrong input password")
			}
			if _, _, _, err := pkcs12.DecodeChain(modern, "wrong"); err == nil {
				t.Fatal("accepted wrong output password")
			}
		})
	}
}

func TestCLI(t *testing.T) {
	key, cert, ca := fixture(t)
	data, err := pkcs12.LegacyRC2.Encode(key, cert, []*x509.Certificate{ca}, "old")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	in, out := filepath.Join(dir, "old.pfx"), filepath.Join(dir, "new.pfx")
	if err := os.WriteFile(in, data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEST_OLD_PASSWORD", "old")
	t.Setenv("TEST_NEW_PASSWORD", "new")
	args := []string{"-in", in, "-out", out, "-in-pass-env", "TEST_OLD_PASSWORD", "-out-pass-env", "TEST_NEW_PASSWORD"}
	if err := run(append([]string{"convert"}, args...), &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if err := run(append([]string{"convert"}, args...), &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("overwrote an existing output")
	}
	after, err := os.ReadFile(out)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("existing output changed")
	}
	t.Setenv("TEST_NEW_PASSWORD", "")
	args[3] = filepath.Join(dir, "empty-password.pfx")
	if err := run(append([]string{"convert"}, args...), &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("accepted empty new password")
	}
	if _, err := os.Stat(args[3]); !os.IsNotExist(err) {
		t.Fatal("created output after failure")
	}
}

func TestOpenSSLInteroperability(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl unavailable")
	}
	key, cert, ca := fixture(t)
	legacy, err := pkcs12.LegacyRC2.Encode(key, cert, []*x509.Certificate{ca}, "old")
	if err != nil {
		t.Fatal(err)
	}
	modern, err := repack(legacy, "old", "new")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	pfx, keyPEMPath := filepath.Join(dir, "new.pfx"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(pfx, modern, 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(openssl, "pkcs12", "-in", pfx, "-passin", "env:TEST_PFX_PASSWORD", "-info", "-noout")
	cmd.Env = append(os.Environ(), "TEST_PFX_PASSWORD=new")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("openssl reading modern PFX: %v\n%s", err, output)
	}
	version, err := exec.Command(openssl, "version").CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	// LibreSSL successfully decrypts this format but omits algorithm names
	// from -info. OpenSSL reports them, so check the profile there as well.
	if !strings.HasPrefix(string(version), "LibreSSL") {
		for _, algorithm := range []string{"sha256", "AES-256-CBC", "Shrouded Keybag: PBES2"} {
			if !strings.Contains(string(output), algorithm) {
				t.Fatalf("missing %s in openssl output: %s", algorithm, output)
			}
		}
	}
	cmd = exec.Command(openssl, "pkcs12", "-in", pfx, "-passin", "env:TEST_PFX_PASSWORD", "-nocerts", "-nodes", "-out", keyPEMPath)
	cmd.Env = append(os.Environ(), "TEST_PFX_PASSWORD=new")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("openssl decrypting key: %v\n%s", err, output)
	}
	decrypted, err := os.ReadFile(keyPEMPath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(decrypted)
	if block == nil {
		t.Fatal("no decrypted key PEM block")
	}
	gotKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil || !key.Equal(gotKey) {
		t.Fatalf("openssl decrypted a different key: %v", err)
	}
}
