package pkcs12

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

// InspectionEntry holds decoded objects for inspection. Private key material
// is deliberately excluded from JSON and must never be printed by callers.
type InspectionEntry struct {
	Type, Alias, LocalKeyID string
	Certificate             *x509.Certificate `json:"-"`
	PrivateKey              any               `json:"-"`
	Protection              *Protection
}

type Protection struct {
	Algorithm  string `json:"algorithm"`
	OID        string `json:"oid,omitempty"`
	Cipher     string `json:"cipher,omitempty"`
	KDF        string `json:"kdf,omitempty"`
	PRF        string `json:"prf,omitempty"`
	Iterations int    `json:"iterations,omitempty"`
}

type Inspection struct {
	Version    int
	Integrity  string
	MAC        *Protection
	Encryption []Protection
	Entries    []InspectionEntry
}

// IsPFX recognizes a PKCS#12 structure, including supported BER wrappers.
func IsPFX(data []byte) bool {
	var pfx pfxPdu
	return unmarshal(data, &pfx) == nil && pfx.Version == 3 && len(pfx.AuthSafe.ContentType) > 0
}

// Inspect reads all supported certificate/key bags, including multiple private
// identities and nested SafeContents. MAC verification is never bypassed.
func Inspect(data []byte, password string) (*Inspection, error) {
	encoded, err := bmpStringZeroTerminated(password)
	if err != nil {
		return nil, err
	}
	bags, encoded, err := getSafeContents(data, encoded, 1, int(^uint(0)>>1))
	if err != nil {
		return nil, err
	}
	var pfx pfxPdu
	if err := unmarshal(data, &pfx); err != nil {
		return nil, err
	}
	info := &Inspection{Version: pfx.Version, Integrity: "not present"}
	if len(pfx.MacData.Mac.Algorithm.Algorithm) > 0 {
		info.Integrity = "verified"
		p, err := describeProtection(pfx.MacData.Mac.Algorithm)
		if err != nil {
			return nil, err
		}
		if !pfx.MacData.Mac.Algorithm.Algorithm.Equal(oidPBMAC1) {
			p.Iterations = pfx.MacData.Iterations
			if p.Iterations == 0 {
				p.Iterations = 1
			}
		}
		info.MAC = &p
	}
	var safeBytes []byte
	if err := unmarshal(pfx.AuthSafe.Content.Bytes, &safeBytes); err != nil {
		return nil, err
	}
	var safe []contentInfo
	if err := unmarshal(safeBytes, &safe); err != nil {
		return nil, err
	}
	for _, content := range safe {
		if content.ContentType.Equal(oidEncryptedDataContentType) {
			var encrypted encryptedData
			if err := unmarshal(content.Content.Bytes, &encrypted); err != nil {
				return nil, err
			}
			p, err := describeProtection(encrypted.EncryptedContentInfo.ContentEncryptionAlgorithm)
			if err != nil {
				return nil, err
			}
			info.Encryption = append(info.Encryption, p)
		}
	}
	if err := inspectBags(info, bags, encoded, 0); err != nil {
		return nil, err
	}
	return info, nil
}

func inspectBags(info *Inspection, bags []safeBag, password []byte, depth int) error {
	if depth > 64 {
		return fmt.Errorf("pkcs12: nested SafeContents limit exceeded")
	}
	for _, bag := range bags {
		if bag.Id.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 6}) {
			var nested []safeBag
			if err := unmarshal(bag.Value.Bytes, &nested); err != nil {
				return err
			}
			if err := inspectBags(info, nested, password, depth+1); err != nil {
				return err
			}
			continue
		}
		entry := InspectionEntry{}
		for _, attribute := range bag.Attributes {
			if attribute.Id.Equal(oidFriendlyName) || attribute.Id.Equal(oidLocalKeyID) {
				name, value, err := convertAttribute(&attribute)
				if err != nil {
					return err
				}
				if name == "friendlyName" {
					entry.Alias = value
				} else {
					entry.LocalKeyID = value
				}
			}
		}
		switch {
		case bag.Id.Equal(oidCertBag):
			der, err := decodeCertBag(bag.Value.Bytes)
			if err != nil {
				return err
			}
			certs, err := x509.ParseCertificates(der)
			if err != nil {
				return err
			}
			for _, cert := range certs {
				copy := entry
				copy.Type = "certificate"
				if bag.hasAttribute(oidJavaTrustStore) {
					copy.Type = "trusted certificate"
				}
				copy.Certificate = cert
				info.Entries = append(info.Entries, copy)
			}
			continue
		case bag.Id.Equal(oidKeyBag):
			key, err := x509.ParsePKCS8PrivateKey(bag.Value.Bytes)
			if err != nil {
				return err
			}
			entry.Type, entry.PrivateKey = "private key", key
		case bag.Id.Equal(oidPKCS8ShroundedKeyBag):
			key, err := decodePkcs8ShroudedKeyBag(bag.Value.Bytes, password)
			if err != nil {
				return err
			}
			entry.Type, entry.PrivateKey = "private key", key
			var encrypted encryptedPrivateKeyInfo
			if err := unmarshal(bag.Value.Bytes, &encrypted); err != nil {
				return err
			}
			p, err := describeProtection(encrypted.AlgorithmIdentifier)
			if err != nil {
				return err
			}
			entry.Protection = &p
		default:
			entry.Type = "unsupported bag (" + bag.Id.String() + ")"
		}
		info.Entries = append(info.Entries, entry)
	}
	return nil
}

// EncryptedKeyProtection detects the ASN.1 EncryptedPrivateKeyInfo structure.
func EncryptedKeyProtection(data []byte) (Protection, error) {
	var info encryptedPrivateKeyInfo
	if err := unmarshal(data, &info); err != nil {
		return Protection{}, err
	}
	if len(info.AlgorithmIdentifier.Algorithm) == 0 || len(info.EncryptedData) == 0 {
		return Protection{}, fmt.Errorf("not an encrypted PKCS#8 key")
	}
	return describeProtection(info.AlgorithmIdentifier)
}

// ParseEncryptedPrivateKey reuses the upstream PKCS#8 decryptor for standalone
// encrypted DER/PEM keys as well as keys held in PKCS#12 bags.
func ParseEncryptedPrivateKey(data []byte, password string) (any, error) {
	encoded, err := bmpStringZeroTerminated(password)
	if err != nil {
		return nil, err
	}
	return decodePkcs8ShroudedKeyBag(data, encoded)
}

func describeProtection(algorithm pkix.AlgorithmIdentifier) (Protection, error) {
	oid := algorithm.Algorithm.String()
	names := map[string]string{
		"1.2.840.113549.1.5.13": "PBES2", "1.2.840.113549.1.5.12": "PBKDF2",
		"1.2.840.113549.1.12.1.3": "SHA-1 / 3DES", "1.2.840.113549.1.12.1.5": "SHA-1 / RC2-128", "1.2.840.113549.1.12.1.6": "SHA-1 / RC2-40",
		"1.3.14.3.2.26": "SHA-1", "2.16.840.1.101.3.4.2.1": "SHA-256", "2.16.840.1.101.3.4.2.2": "SHA-384", "2.16.840.1.101.3.4.2.3": "SHA-512",
		"1.2.840.113549.1.5.14": "PBMAC1",
	}
	p := Protection{Algorithm: names[oid], OID: oid}
	if p.Algorithm == "" {
		p.Algorithm = oid
	}
	if algorithm.Algorithm.Equal(oidPBMAC1) {
		var params pbmac1Params
		if err := unmarshal(algorithm.Parameters.FullBytes, &params); err != nil {
			return p, err
		}
		p.KDF = params.Kdf.Algorithm.String()
		if params.Kdf.Algorithm.Equal(oidPBKDF2) {
			p.KDF = "PBKDF2"
			var kdf pbkdf2Params
			if err := unmarshal(params.Kdf.Parameters.FullBytes, &kdf); err != nil {
				return p, err
			}
			p.Iterations = kdf.Iterations
		}
		p.PRF = params.MacAlg.Algorithm.String()
		switch {
		case params.MacAlg.Algorithm.Equal(oidHmacWithSHA1):
			p.PRF = "HMAC-SHA-1"
		case params.MacAlg.Algorithm.Equal(oidHmacWithSHA256):
			p.PRF = "HMAC-SHA-256"
		case params.MacAlg.Algorithm.Equal(oidHmacWithSHA512):
			p.PRF = "HMAC-SHA-512"
		}
	} else if algorithm.Algorithm.Equal(oidPBES2) {
		var params pbes2Params
		if err := unmarshal(algorithm.Parameters.FullBytes, &params); err != nil {
			return p, err
		}
		p.KDF = params.Kdf.Algorithm.String()
		if params.Kdf.Algorithm.Equal(oidPBKDF2) {
			p.KDF = "PBKDF2"
			var kdf pbkdf2Params
			if err := unmarshal(params.Kdf.Parameters.FullBytes, &kdf); err != nil {
				return p, err
			}
			p.Iterations = kdf.Iterations
			p.PRF = kdf.Prf.Algorithm.String()
			switch {
			case len(kdf.Prf.Algorithm) == 0 || kdf.Prf.Algorithm.Equal(oidHmacWithSHA1):
				p.PRF = "HMAC-SHA-1"
			case kdf.Prf.Algorithm.Equal(oidHmacWithSHA256):
				p.PRF = "HMAC-SHA-256"
			case kdf.Prf.Algorithm.Equal(oidHmacWithSHA512):
				p.PRF = "HMAC-SHA-512"
			}
		}
		p.Cipher = params.EncryptionScheme.Algorithm.String()
		switch {
		case params.EncryptionScheme.Algorithm.Equal(oidAES128CBC):
			p.Cipher = "AES-128-CBC"
		case params.EncryptionScheme.Algorithm.Equal(oidAES192CBC):
			p.Cipher = "AES-192-CBC"
		case params.EncryptionScheme.Algorithm.Equal(oidAES256CBC):
			p.Cipher = "AES-256-CBC"
		}
	} else if algorithm.Algorithm.Equal(oidPBEWithSHAAnd3KeyTripleDESCBC) || algorithm.Algorithm.Equal(oidPBEWithSHAAnd128BitRC2CBC) || algorithm.Algorithm.Equal(oidPBEWithSHAAnd40BitRC2CBC) {
		var params pbeParams
		if err := unmarshal(algorithm.Parameters.FullBytes, &params); err != nil {
			return p, err
		}
		p.Iterations = params.Iterations
	}
	return p, nil
}
