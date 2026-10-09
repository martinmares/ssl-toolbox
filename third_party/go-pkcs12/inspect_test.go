package pkcs12

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"
)

func inspectFixture(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

func TestInspectMultipleIdentitiesAndNestedBags(t *testing.T) {
	password, _ := bmpStringZeroTerminated("secret")
	var combined []contentInfo
	var pfx pfxPdu
	for i := 0; i < 2; i++ {
		key, cert := inspectFixture(t)
		der, err := Modern2023.Encode(key, cert, nil, "secret")
		if err != nil {
			t.Fatal(err)
		}
		if err := unmarshal(der, &pfx); err != nil {
			t.Fatal(err)
		}
		var safeBytes []byte
		if err := unmarshal(pfx.AuthSafe.Content.Bytes, &safeBytes); err != nil {
			t.Fatal(err)
		}
		var contents []contentInfo
		if err := unmarshal(safeBytes, &contents); err != nil {
			t.Fatal(err)
		}
		combined = append(combined, contents...)
	}
	// A nested raw key bag must be enumerated too, not silently skipped.
	key, _ := inspectFixture(t)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	inner := []safeBag{{Id: oidKeyBag, Value: asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: keyDER}}}
	nestedDER, err := asn1.Marshal(inner)
	if err != nil {
		t.Fatal(err)
	}
	nested := safeBag{Id: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 6}, Value: asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: nestedDER}}
	ci, err := makeSafeContents(rand.Reader, []safeBag{nested}, nil, nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	combined = append(combined, ci)
	safeBytes, err := asn1.Marshal(combined)
	if err != nil {
		t.Fatal(err)
	}
	if err := computeMac(&pfx.MacData, safeBytes, password); err != nil {
		t.Fatal(err)
	}
	pfx.AuthSafe.Content.FullBytes = nil
	pfx.AuthSafe.Content.Bytes, err = asn1.Marshal(safeBytes)
	if err != nil {
		t.Fatal(err)
	}
	der, err := asn1.Marshal(pfx)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range [][]byte{der, toIndefinite(t, der)} {
		if !IsPFX(input) {
			t.Fatal("not recognized")
		}
		info, err := Inspect(input, "secret")
		if err != nil {
			t.Fatal(err)
		}
		certs, keys := 0, 0
		for _, e := range info.Entries {
			if e.Certificate != nil {
				certs++
			}
			if e.PrivateKey != nil {
				keys++
			}
		}
		if certs != 2 || keys != 3 || info.Integrity != "verified" {
			t.Fatalf("missing objects: %d %d", certs, keys)
		}
		if _, err := Inspect(input, "wrong"); !errors.Is(err, ErrIncorrectPassword) {
			t.Fatalf("MAC bypassed: %v", err)
		}
	}
}

func TestInspectEncryptedPKCS8(t *testing.T) {
	key, _ := inspectFixture(t)
	pw, _ := bmpStringZeroTerminated("secret")
	for _, algo := range []asn1.ObjectIdentifier{oidPBES2, oidPBEWithSHAAnd3KeyTripleDESCBC} {
		der, err := encodePkcs8ShroudedKeyBag(rand.Reader, key, algo, pw, 2048, 16)
		if err != nil {
			t.Fatal(err)
		}
		p, err := EncryptedKeyProtection(der)
		if err != nil || p.Iterations != 2048 {
			t.Fatalf("protection: %+v %v", p, err)
		}
		got, err := ParseEncryptedPrivateKey(der, "secret")
		if err != nil || !key.Equal(got) {
			t.Fatalf("key changed: %v", err)
		}
		if _, err := ParseEncryptedPrivateKey(der, "wrong"); err == nil {
			t.Fatal("accepted wrong password")
		}
	}
	params, err := makePBMAC1Parameters([]byte("salt"), 5678)
	if err != nil {
		t.Fatal(err)
	}
	p, err := describeProtection(pkix.AlgorithmIdentifier{Algorithm: oidPBMAC1, Parameters: asn1.RawValue{FullBytes: params}})
	if err != nil || p.Iterations != 5678 || p.KDF != "PBKDF2" {
		t.Fatalf("PBMAC1: %+v %v", p, err)
	}
}
