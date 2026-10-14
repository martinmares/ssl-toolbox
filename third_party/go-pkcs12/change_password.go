package pkcs12

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
)

// ChangePassword re-encrypts every key and the authenticated safe, retaining
// certificates, bag order, attributes (including aliases/localKeyIDs), and
// nested SafeContents. Multiple identities and trusted entries are supported.
func (enc *Encoder) ChangePassword(data []byte, oldPassword, newPassword string) ([]byte, error) {
	if enc.keyAlgorithm == nil || enc.certAlgorithm == nil || enc.macAlgorithm == nil {
		return nil, errors.New("pkcs12: password change requires encryption and MAC protection")
	}
	oldEncoded, err := bmpStringZeroTerminated(oldPassword)
	if err != nil {
		return nil, err
	}
	bags, oldEncoded, err := getSafeContents(data, oldEncoded, 1, int(^uint(0)>>1))
	if err != nil {
		return nil, err
	}
	newEncoded, err := bmpStringZeroTerminated(newPassword)
	if err != nil {
		return nil, err
	}
	if err := enc.changeBagPasswords(bags, oldEncoded, newEncoded, 0); err != nil {
		return nil, err
	}
	return enc.encodeSafeBags(bags, newEncoded)
}

func (enc *Encoder) changeBagPasswords(bags []safeBag, oldPassword, newPassword []byte, depth int) error {
	if depth > 64 {
		return errors.New("pkcs12: nested SafeContents limit exceeded")
	}
	for i := range bags {
		bag := &bags[i]
		var der []byte
		var err error
		switch {
		case bag.Id.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 6}):
			var nested []safeBag
			if err := unmarshal(bag.Value.Bytes, &nested); err != nil {
				return err
			}
			if err := enc.changeBagPasswords(nested, oldPassword, newPassword, depth+1); err != nil {
				return err
			}
			der, err = asn1.Marshal(nested)
		case bag.Id.Equal(oidKeyBag), bag.Id.Equal(oidPKCS8ShroundedKeyBag):
			var key any
			if bag.Id.Equal(oidKeyBag) {
				key, err = x509.ParsePKCS8PrivateKey(bag.Value.Bytes)
			} else {
				key, err = decodePkcs8ShroudedKeyBag(bag.Value.Bytes, oldPassword)
			}
			if err != nil {
				return err
			}
			der, err = encodePkcs8ShroudedKeyBag(enc.rand, key, enc.keyAlgorithm, newPassword, enc.encryptionIterations, enc.saltLen)
			bag.Id = oidPKCS8ShroundedKeyBag
		default:
			continue
		}
		if err != nil {
			return err
		}
		bag.Value = asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: der}
	}
	return nil
}
