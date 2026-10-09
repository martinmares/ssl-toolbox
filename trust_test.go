package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
	"software.sslmate.com/src/go-pkcs12"
)

func certPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func TestReadCAs(t *testing.T) {
	_, leaf, ca := fixture(t)
	_, _, anotherCA := fixture(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "ca.pem")
	bundle := append(certPEM(ca), certPEM(anotherCA)...)
	bundle = append(bundle, certPEM(ca)...)
	if err := os.WriteFile(path, bundle, 0600); err != nil {
		t.Fatal(err)
	}
	certs, err := readCAs([]string{path, path})
	if err != nil || len(certs) != 2 || !ca.Equal(certs[0]) || !anotherCA.Equal(certs[1]) {
		t.Fatalf("bundle/dedup failed: %v", err)
	}
	for name, data := range map[string][]byte{
		"empty":           nil,
		"leaf":            certPEM(leaf),
		"junk":            []byte("not a PEM"),
		"trailing junk":   append(certPEM(ca), []byte("unexpected")...),
		"invalid DER":     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}}),
		"key block":       pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}}),
		"bad first block": append([]byte("-----BEGIN CERTIFICATE-----\n!invalid!\n-----END CERTIFICATE-----\n"), certPEM(ca)...),
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := readCAs([]string{path}); err == nil {
				t.Fatal("accepted invalid CA file")
			}
		})
	}
	if _, err := readCAs([]string{filepath.Join(dir, "missing.pem")}); err == nil {
		t.Fatal("accepted missing CA file")
	}
}

func TestAddCAAndTruststore(t *testing.T) {
	key, cert, ca := fixture(t)
	_, _, anotherCA := fixture(t)
	dir := t.TempDir()
	pfx, err := pkcs12.LegacyRC2.Encode(key, cert, []*x509.Certificate{ca}, "old password")
	if err != nil {
		t.Fatal(err)
	}
	in := filepath.Join(dir, "input.pfx")
	bundle := filepath.Join(dir, "bundle.pem")
	repeated := filepath.Join(dir, "repeated.pem")
	for path, data := range map[string][]byte{in: pfx, bundle: append(certPEM(ca), certPEM(anotherCA)...), repeated: certPEM(ca)} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("TEST_OLD_PASSWORD", "old password")
	t.Setenv("TEST_NEW_PASSWORD", "new password")
	for _, format := range []string{"pfx", "jks"} {
		for _, mixed := range []bool{false, true} {
			name := format + "-truststore"
			if mixed {
				name = format + "-mixed"
			}
			t.Run(name, func(t *testing.T) {
				out := filepath.Join(t.TempDir(), "out."+format)
				args := []string{"truststore", "--out", out, "--format", format, "--add-ca", bundle, "--add-ca", repeated, "--out-pass-env", "TEST_NEW_PASSWORD"}
				if mixed {
					args[0] = "convert"
					args = append(args, "--in", in, "--in-pass-env", "TEST_OLD_PASSWORD")
				}
				if err := run(args, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
					t.Fatal(err)
				}
				data, err := os.ReadFile(out)
				if err != nil {
					t.Fatal(err)
				}
				var trusts []*x509.Certificate
				if format == "pfx" {
					gotKey, gotCert, chain, entries, err := pkcs12.DecodeWithTrust(data, "new password")
					if err != nil {
						t.Fatal(err)
					}
					for _, entry := range entries {
						trusts = append(trusts, entry.Cert)
					}
					if mixed {
						if !key.Equal(gotKey) || !cert.Equal(gotCert) || len(chain) != 1 || !ca.Equal(chain[0]) {
							t.Fatal("identity or chain changed")
						}
					} else if gotKey != nil || gotCert != nil || len(chain) != 0 {
						t.Fatal("truststore unexpectedly contains an identity")
					}
					if _, _, _, _, err := pkcs12.DecodeWithTrust(data, "wrong password"); err == nil {
						t.Fatal("accepted wrong password")
					}
					if !mixed {
						if certs, err := pkcs12.DecodeTrustStore(data, "new password"); err != nil || len(certs) != 2 {
							t.Fatalf("not a Java truststore: %v", err)
						}
					}
					// A second conversion must preserve trusted roles, including when
					// the same CA is present in the client's chain and in the truststore.
					again, err := convert(data, "new password", "next password", "pfx", "client")
					if err != nil {
						t.Fatal(err)
					}
					_, _, againChain, againTrusts, err := pkcs12.DecodeWithTrust(again, "next password")
					if err != nil || len(againTrusts) != 2 || len(againChain) != (map[bool]int{true: 1, false: 0}[mixed]) {
						t.Fatalf("trust roles lost during repack: %v", err)
					}
				} else {
					ks := keystore.New()
					if err := ks.Load(bytes.NewReader(data), []byte("new password")); err != nil {
						t.Fatal(err)
					}
					for _, alias := range ks.Aliases() {
						if ks.IsTrustedCertificateEntry(alias) {
							entry, err := ks.GetTrustedCertificateEntry(alias)
							if err != nil {
								t.Fatal(err)
							}
							parsed, err := x509.ParseCertificate(entry.Certificate.Content)
							if err != nil {
								t.Fatal(err)
							}
							trusts = append(trusts, parsed)
						}
					}
					if mixed {
						entry, err := ks.GetPrivateKeyEntry("client", []byte("new password"))
						if err != nil {
							t.Fatal(err)
						}
						gotKey, err := x509.ParsePKCS8PrivateKey(entry.PrivateKey)
						if err != nil || !key.Equal(gotKey) || len(entry.CertificateChain) != 2 || !bytes.Equal(entry.CertificateChain[0].Content, cert.Raw) || !bytes.Equal(entry.CertificateChain[1].Content, ca.Raw) {
							t.Fatal("JKS identity changed")
						}
					}
					wantEntries := 2
					if mixed {
						wantEntries++
					}
					if len(ks.Aliases()) != wantEntries {
						t.Fatal("unexpected JKS entries")
					}
				}
				if len(trusts) != 2 {
					t.Fatalf("want two unique trust anchors; got %d", len(trusts))
				}
				for _, expected := range []*x509.Certificate{ca, anotherCA} {
					found := false
					for _, got := range trusts {
						if expected.Equal(got) {
							found = true
						}
					}
					if !found {
						t.Fatal("missing trusted CA")
					}
				}
				t.Run("Java", func(t *testing.T) {
					keytool, err := exec.LookPath("keytool")
					if err != nil {
						t.Skip("keytool unavailable")
					}
					storetype := "PKCS12"
					if format == "jks" {
						storetype = "JKS"
					}
					cmd := exec.Command(keytool, "-J-Duser.language=en", "-J-Duser.country=US", "-list", "-v", "-keystore", out, "-storetype", storetype, "-storepass:env", "TEST_NEW_PASSWORD")
					output, err := cmd.CombinedOutput()
					if err != nil {
						t.Fatalf("Java reading output: %v\n%s", err, output)
					}
					if strings.Count(string(output), "Entry type: trustedCertEntry") != 2 {
						t.Fatalf("Java did not see two trusted CA entries:\n%s", output)
					}
					wantKeys := 0
					if mixed {
						wantKeys = 1
					}
					if strings.Count(string(output), "Entry type: PrivateKeyEntry") != wantKeys {
						t.Fatalf("unexpected Java key entries:\n%s", output)
					}
					if mixed {
						// Decrypt and re-export every entry through Java, verifying both
						// the new key password and Java's trust attributes.
						javaOut := filepath.Join(t.TempDir(), "java.pfx")
						cmd = exec.Command(keytool, "-importkeystore", "-srckeystore", out, "-srcstoretype", storetype, "-srcstorepass:env", "TEST_NEW_PASSWORD", "-destkeystore", javaOut, "-deststoretype", "PKCS12", "-deststorepass:env", "TEST_NEW_PASSWORD", "-noprompt")
						if output, err := cmd.CombinedOutput(); err != nil {
							t.Fatalf("Java decrypt/import failed: %v\n%s", err, output)
						}
						exported, err := os.ReadFile(javaOut)
						if err != nil {
							t.Fatal(err)
						}
						gotKey, gotCert, chain, trusted, err := pkcs12.DecodeWithTrust(exported, "new password")
						if err != nil || !key.Equal(gotKey) || !cert.Equal(gotCert) || len(chain) != 1 || !ca.Equal(chain[0]) || len(trusted) != 2 {
							t.Fatalf("Java roundtrip changed entries: %v", err)
						}
					}
				})
			})
		}
	}
}

func TestAddCAFailureDoesNotCreateOutput(t *testing.T) {
	_, leaf, ca := fixture(t)
	dir := t.TempDir()
	bad := filepath.Join(dir, "leaf.pem")
	out := filepath.Join(dir, "out.pfx")
	if err := os.WriteFile(bad, certPEM(leaf), 0600); err != nil {
		t.Fatal(err)
	}
	// No passwords supplied: invalid CAs must be rejected before prompting.
	if err := run([]string{"truststore", "--out", out, "--add-ca", bad}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("accepted leaf as CA")
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("created output after invalid input")
	}
	key, cert, chainCA := fixture(t)
	pfx, err := pkcs12.Modern2023.Encode(key, cert, []*x509.Certificate{chainCA}, "old")
	if err != nil {
		t.Fatal(err)
	}
	alias := uniqueTrustEntries([]pkcs12.TrustStoreEntry{{Cert: ca}})[0].FriendlyName
	if _, err := convertWithCAs(pfx, "old", "new password", "jks", alias, []*x509.Certificate{ca}); err == nil {
		t.Fatal("silently replaced key with trusted entry on alias collision")
	}
}
