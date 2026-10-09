package pkcs12

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"
)

func TestNormalizeBER(t *testing.T) {
	for _, tt := range []struct {
		name     string
		ber, der []byte
	}{
		{"nested", []byte{0x30, 0x80, 0xa0, 0x80, 4, 2, 0x30, 0x80, 0, 0, 0, 0}, []byte{0x30, 6, 0xa0, 4, 4, 2, 0x30, 0x80}},
		{"chunked octets", []byte{0x24, 0x80, 4, 2, 0x30, 0x80, 0x24, 3, 4, 1, 0, 0, 0}, []byte{4, 3, 0x30, 0x80, 0}},
		{"long length", []byte{4, 0x82, 0, 1, 42}, []byte{4, 1, 42}},
		{"empty", []byte{0x30, 0x80, 0, 0}, []byte{0x30, 0}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeBER(tt.ber)
			if err != nil || !bytes.Equal(got, tt.der) {
				t.Fatalf("got %x, %v; want %x", got, err, tt.der)
			}
		})
	}
	for _, data := range [][]byte{
		nil, {0x30}, {0x1f, 1}, {0x30, 0x80}, {4, 0x80, 0, 0},
		{0x30, 1, 4}, {0x30, 2, 0, 0}, {4, 0x88, 255, 255, 255, 255, 255, 255, 255, 255},
		{0x24, 0x80, 2, 1, 1, 0, 0}, {4, 0, 4, 0},
	} {
		if _, err := normalizeBER(data); err == nil {
			t.Errorf("accepted malformed BER: %x", data)
		}
	}
	deep := []byte{4, 0}
	for i := 0; i < 70; i++ {
		deep = append(append([]byte{0x30, 0x80}, deep...), 0, 0)
	}
	if _, err := normalizeBER(deep); err == nil {
		t.Error("accepted excessive nesting")
	}
}

// toIndefinite changes every constructed DER wrapper, leaving opaque
// primitive payloads untouched. AuthenticatedSafe is converted separately.
func toIndefinite(t *testing.T, der []byte) []byte {
	t.Helper()
	var out []byte
	for len(der) > 0 {
		var raw asn1.RawValue
		rest, err := asn1.Unmarshal(der, &raw)
		if err != nil {
			t.Fatal(err)
		}
		if raw.IsCompound {
			out = append(out, raw.FullBytes[0], 0x80)
			out = append(out, toIndefinite(t, raw.Bytes)...)
			out = append(out, 0, 0)
		} else {
			out = append(out, raw.FullBytes...)
		}
		der = rest
	}
	return out
}

func TestDecodeBERWithOriginalMAC(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	for name, encoder := range map[string]*Encoder{"rc2": LegacyRC2, "modern": Modern2023} {
		t.Run(name, func(t *testing.T) {
			der, err := encoder.Encode(key, cert, nil, "password")
			if err != nil {
				t.Fatal(err)
			}
			var pfx pfxPdu
			if err := unmarshal(der, &pfx); err != nil {
				t.Fatal(err)
			}
			var authSafe []byte
			if err := unmarshal(pfx.AuthSafe.Content.Bytes, &authSafe); err != nil {
				t.Fatal(err)
			}
			authSafe = toIndefinite(t, authSafe)
			password, err := bmpStringZeroTerminated("password")
			if err != nil {
				t.Fatal(err)
			}
			// A BER-producing exporter signs the BER bytes, not a DER rewrite.
			if err := computeMac(&pfx.MacData, authSafe, password); err != nil {
				t.Fatal(err)
			}
			for _, chunked := range []bool{false, true} {
				octets, err := asn1.Marshal(authSafe)
				if err != nil {
					t.Fatal(err)
				}
				if chunked {
					first, _ := asn1.Marshal(authSafe[:len(authSafe)/2])
					second, _ := asn1.Marshal(authSafe[len(authSafe)/2:])
					octets = append([]byte{0x24, 0x80}, first...)
					octets = append(octets, second...)
					octets = append(octets, 0, 0)
				}
				pfx.AuthSafe.Content = asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: octets}
				outer, err := asn1.Marshal(pfx)
				if err != nil {
					t.Fatal(err)
				}
				// The chunked octets are already BER, so leave their outer DER
				// wrappers alone in that case.
				if !chunked {
					outer = toIndefinite(t, outer)
				}
				gotKey, gotCert, _, err := DecodeChain(outer, "password")
				if err != nil || !key.Equal(gotKey) || !cert.Equal(gotCert) {
					t.Fatalf("BER decode failed (chunked=%v): %v", chunked, err)
				}
				if _, _, _, err := DecodeChain(outer, "wrong"); !errors.Is(err, ErrIncorrectPassword) {
					t.Fatalf("wrong password was not rejected by MAC: %v", err)
				}
				// Alter authenticated content while keeping valid outer ASN.1.
				tampered := append([]byte(nil), outer...)
				start := bytes.Index(tampered, authSafe[:16])
				if start < 0 {
					t.Fatal("cannot locate authenticated payload")
				}
				tampered[start+10] ^= 1
				if _, _, _, err := DecodeChain(tampered, "password"); !errors.Is(err, ErrIncorrectPassword) {
					t.Fatalf("tampered content was not rejected by MAC: %v", err)
				}
			}
		})
	}
}

func FuzzNormalizeBER(f *testing.F) {
	f.Add([]byte{0x30, 0x80, 4, 1, 42, 0, 0})
	f.Add([]byte{0x24, 0x80, 4, 1, 42, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := normalizeBER(data)
		if err != nil {
			return
		}
		again, err := normalizeBER(got)
		if err != nil || !bytes.Equal(got, again) {
			t.Fatalf("normalization is not idempotent: %v", err)
		}
	})
}
