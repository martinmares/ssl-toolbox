package main

import (
	"bytes"
	"crypto/x509"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"software.sslmate.com/src/go-pkcs12"
)

func TestPFXChangePasswordInPlace(t *testing.T) {
	for _, source := range []string{"env", "file"} {
		t.Run(source, func(t *testing.T) {
			key, cert, ca := fixture(t)
			_, _, trustedCA := fixture(t)
			original, err := pkcs12.LegacyRC2.EncodeWithTrust(key, cert, []*x509.Certificate{ca}, []pkcs12.TrustStoreEntry{{Cert: trustedCA, FriendlyName: "extra-ca"}}, "old-secret")
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			path := filepath.Join(dir, "client.pfx")
			if err := os.WriteFile(path, original, 0640); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PFX_OLD_PASSWORD", "old-secret")
			t.Setenv("PFX_NEW_PASSWORD", "new-secret")
			flags := []string{"--in-pass-env", "PFX_OLD_PASSWORD", "--out-pass-env", "PFX_NEW_PASSWORD"}
			if source == "file" {
				for name, value := range map[string]string{"old.txt": "old-secret\n", "new.txt": "new-secret\r\n"} {
					if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0600); err != nil {
						t.Fatal(err)
					}
				}
				flags = []string{"--in-pass-file", filepath.Join(dir, "old.txt"), "--out-pass-file", filepath.Join(dir, "new.txt")}
			}
			var stdout bytes.Buffer
			if err := run(append([]string{"pfx", "change-password", path}, flags...), &stdout, &bytes.Buffer{}); err != nil {
				t.Fatal(err)
			}
			updated, err := os.ReadFile(path)
			if err != nil || bytes.Equal(original, updated) {
				t.Fatalf("PFX not replaced: %v", err)
			}
			newKey, newCert, chain, trusted, err := pkcs12.DecodeWithTrust(updated, "new-secret")
			if err != nil || !bytes.Equal(cert.Raw, newCert.Raw) || len(chain) != 1 || !bytes.Equal(chain[0].Raw, ca.Raw) || len(trusted) != 1 || !bytes.Equal(trusted[0].Cert.Raw, trustedCA.Raw) || trusted[0].FriendlyName != "extra-ca" {
				t.Fatalf("identity, chain or trust entry changed: %v", err)
			}
			oldKeyDER, _ := x509.MarshalPKCS8PrivateKey(key)
			newKeyDER, _ := x509.MarshalPKCS8PrivateKey(newKey)
			if !bytes.Equal(oldKeyDER, newKeyDER) {
				t.Fatal("private key changed")
			}
			if _, err := pkcs12.Inspect(updated, "old-secret"); err == nil {
				t.Fatal("old password still accepted")
			}
			report := inspectTestData(t, updated, "new-secret", "")
			if report.MAC.Algorithm != "SHA-256" || report.PrivateKeyCount != 1 {
				t.Fatal("expected modern PFX with a decryptable private key")
			}
			if runtime.GOOS != "windows" {
				info, _ := os.Stat(path)
				if info.Mode().Perm() != 0640 {
					t.Fatal("file permissions changed")
				}
			}
			if matches, _ := filepath.Glob(filepath.Join(dir, ".ssl-toolbox-pfx-*")); len(matches) != 0 {
				t.Fatal("temporary file left behind")
			}
			if strings.Contains(stdout.String(), "old-secret") || strings.Contains(stdout.String(), "new-secret") {
				t.Fatal("password printed")
			}
			if openssl, err := exec.LookPath("openssl"); err == nil {
				if out, err := exec.Command(openssl, "pkcs12", "-in", path, "-passin", "env:PFX_NEW_PASSWORD", "-info", "-noout").CombinedOutput(); err != nil {
					t.Fatalf("OpenSSL rejected the replaced PFX: %v %s", err, out)
				}
			}
		})
	}
}

func TestPFXChangePasswordTruststoreAndSymlink(t *testing.T) {
	_, _, ca := fixture(t)
	data, err := pkcs12.Legacy.EncodeTrustStoreEntries([]pkcs12.TrustStoreEntry{{Cert: ca, FriendlyName: "original-ca"}}, "old-secret")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "truststore.pfx")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PFX_STORE_OLD", "old-secret")
	t.Setenv("PFX_STORE_NEW", "new-secret")
	flags := []string{"--in-pass-env", "PFX_STORE_OLD", "--out-pass-env", "PFX_STORE_NEW"}
	if err := run(append([]string{"pfx", "change-password", path}, flags...), &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	updated, _ := os.ReadFile(path)
	_, _, _, entries, err := pkcs12.DecodeWithTrust(updated, "new-secret")
	if err != nil || len(entries) != 1 || entries[0].FriendlyName != "original-ca" || !bytes.Equal(entries[0].Cert.Raw, ca.Raw) {
		t.Fatalf("truststore changed: %v", err)
	}
	if err := run(append([]string{"pfx", "change-password", dir}, flags...), &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("accepted directory input")
	}
	link := filepath.Join(dir, "link.pfx")
	if err := os.Symlink(path, link); err != nil {
		t.Log("symlink check omitted: ", err)
		return
	}
	if err := run(append([]string{"pfx", "change-password", link}, flags...), &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("accepted symlink input")
	}
	current, _ := os.ReadFile(path)
	if !bytes.Equal(current, updated) {
		t.Fatal("modified symlink target")
	}
}

func TestPFXChangePasswordFailuresKeepOriginal(t *testing.T) {
	key, cert, ca := fixture(t)
	original, err := pkcs12.Modern2023.Encode(key, cert, []*x509.Certificate{ca}, "old-secret")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PFX_OLD_PASSWORD", "old-secret")
	t.Setenv("PFX_WRONG_PASSWORD", "wrong")
	t.Setenv("PFX_EMPTY_PASSWORD", "")
	t.Setenv("PFX_NEW_PASSWORD", "new-secret")
	for _, flags := range [][]string{
		{"--in-pass-env", "PFX_WRONG_PASSWORD", "--out-pass-env", "PFX_NEW_PASSWORD"},
		{"--in-pass-env", "PFX_OLD_PASSWORD", "--out-pass-env", "PFX_EMPTY_PASSWORD"},
		{"--in-pass-env", "PFX_OLD_PASSWORD", "--out-pass-env", "MISSING_PFX_NEW_PASSWORD"},
		{"--in-pass-env", "PFX_OLD_PASSWORD", "--in-pass-file", "missing", "--out-pass-env", "PFX_NEW_PASSWORD"},
	} {
		dir := t.TempDir()
		path := filepath.Join(dir, "client.pfx")
		if err := os.WriteFile(path, original, 0600); err != nil {
			t.Fatal(err)
		}
		if err := run(append([]string{"pfx", "change-password", path}, flags...), &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
			t.Fatalf("accepted invalid password options: %v", flags)
		}
		data, _ := os.ReadFile(path)
		if !bytes.Equal(data, original) {
			t.Fatal("changed original on failure")
		}
	}
}

func TestPFXReplacementVerificationAndConcurrentUpdate(t *testing.T) {
	key, cert, ca := fixture(t)
	original, err := pkcs12.Modern2023.Encode(key, cert, []*x509.Certificate{ca}, "old-secret")
	if err != nil {
		t.Fatal(err)
	}
	updated, err := repack(original, "old-secret", "new-secret")
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"invalid-temporary", "wrong-new-password", "concurrent-update"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "client.pfx")
			if err := os.WriteFile(path, original, 0600); err != nil {
				t.Fatal(err)
			}
			info, _ := os.Lstat(path)
			data, pw, want := updated, "new-secret", original
			switch scenario {
			case "invalid-temporary":
				data = []byte("not a PFX")
			case "wrong-new-password":
				pw = "wrong"
			case "concurrent-update":
				want = []byte("concurrent change")
				if err := os.WriteFile(path, want, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := replacePFXPasswordFile(path, info, original, data, pw); err == nil {
				t.Fatal("replaced despite verification failure or concurrent update")
			}
			stored, _ := os.ReadFile(path)
			if !bytes.Equal(stored, want) {
				t.Fatal("existing file modified")
			}
			if matches, _ := filepath.Glob(filepath.Join(dir, ".ssl-toolbox-pfx-*")); len(matches) != 0 {
				t.Fatal("temporary file not cleaned up")
			}
		})
	}
}
