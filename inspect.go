package main

import (
	"bytes"
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
	"github.com/spf13/cobra"
	"software.sslmate.com/src/go-pkcs12"
)

type inspectionReport struct {
	ExpiryWarningDays int                 `json:"expiry_warning_days"`
	File              string              `json:"file"`
	Format            string              `json:"format"`
	StoreVersion      int                 `json:"store_version,omitempty"`
	Integrity         string              `json:"integrity"`
	MAC               *pkcs12.Protection  `json:"mac,omitempty"`
	Encryption        []pkcs12.Protection `json:"encryption,omitempty"`
	EntryCount        int                 `json:"entry_count"`
	CertificateCount  int                 `json:"certificate_count"`
	PrivateKeyCount   int                 `json:"private_key_count"`
	PublicKeyCount    int                 `json:"public_key_count"`
	Entries           []inspectionEntry   `json:"entries"`
}

type inspectionEntry struct {
	ID          string              `json:"id"`
	Type        string              `json:"type"`
	Alias       string              `json:"alias,omitempty"`
	LocalKeyID  string              `json:"local_key_id,omitempty"`
	Created     *time.Time          `json:"created,omitempty"`
	Protection  *pkcs12.Protection  `json:"protection,omitempty"`
	PublicKey   *publicKeyDetails   `json:"public_key,omitempty"`
	Certificate *certificateDetails `json:"certificate,omitempty"`
	Matches     []string            `json:"matching_entries,omitempty"`
}

type publicKeyDetails struct {
	Algorithm string `json:"algorithm"`
	Bits      int    `json:"bits,omitempty"`
	Curve     string `json:"curve,omitempty"`
	SHA256    string `json:"spki_sha256"`
}

type certificateDetails struct {
	ExpiresInSeconds            int64     `json:"expires_in_seconds"`
	Subject                     string    `json:"subject"`
	Issuer                      string    `json:"issuer"`
	Serial                      string    `json:"serial_hex"`
	Version                     int       `json:"version"`
	NotBefore                   time.Time `json:"not_before"`
	NotAfter                    time.Time `json:"not_after"`
	Validity                    string    `json:"validity"`
	SignatureAlgorithm          string    `json:"signature_algorithm"`
	SHA256                      string    `json:"sha256"`
	IsCA                        bool      `json:"is_ca"`
	BasicConstraintsValid       bool      `json:"basic_constraints_valid"`
	MaxPathLen                  *int      `json:"max_path_length,omitempty"`
	KeyUsage                    []string  `json:"key_usage"`
	ExtendedKeyUsage            []string  `json:"extended_key_usage"`
	SAN                         []string  `json:"subject_alt_names"`
	SelfSigned                  bool      `json:"self_signed"`
	UnhandledCriticalExtensions []string  `json:"unhandled_critical_extensions,omitempty"`
}

type inspectPassword struct {
	env, file, value string
	set              bool
	stderr           io.Writer
}

func (p *inspectPassword) provided() bool { return p.env != "" || p.file != "" }

func (p *inspectPassword) read(prompt string, refresh bool) (string, error) {
	if p.set && (!refresh || p.provided()) {
		return p.value, nil
	}
	value, err := readPasswordSource(p.env, p.file, prompt, p.stderr)
	if err != nil {
		return "", err
	}
	p.value, p.set = value, true
	return value, nil
}

func newInspectCommand(stdout, stderr io.Writer) *cobra.Command {
	var passEnv, keyPassEnv, passFile, keyPassFile string
	var asJSON bool
	colorMode := "auto"
	expiryDays := 30
	cmd := &cobra.Command{Use: "inspect <file>", Short: "Identify and inspect every certificate and key without printing private material", Args: cobra.ExactArgs(1),
		Example: "  ssl-toolbox inspect client.pfx\n  ssl-toolbox inspect truststore.jks --pass-env STORE_PASSWORD\n  ssl-toolbox inspect ca-bundle.pem --json",
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			color, err := colorEnabled(stdout, colorMode)
			if err != nil {
				return err
			}
			if expiryDays < 0 {
				return errors.New("--expiry-warning-days must not be negative")
			}
			data, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("read inspected file: %w", err)
			}
			storePassword := &inspectPassword{env: passEnv, file: passFile, stderr: stderr}
			keyPassword := &inspectPassword{env: keyPassEnv, file: keyPassFile, stderr: stderr}
			report, err := inspectContents(data, storePassword, keyPassword)
			if err != nil {
				return err
			}
			report.File = args[0]
			applyExpiryStatus(report, time.Now(), expiryDays)
			if asJSON {
				encoder := json.NewEncoder(stdout)
				encoder.SetIndent("", "  ")
				return encoder.Encode(report)
			}
			return printInspectionColored(stdout, report, color)
		},
	}
	cmd.Flags().StringVar(&passEnv, "pass-env", "", "Environment variable with store/encrypted PEM password; otherwise prompt if needed")
	cmd.Flags().StringVar(&keyPassEnv, "key-pass-env", "", "JKS private-key password variable, if different from the store password")
	cmd.Flags().StringVar(&passFile, "pass-file", "", "File containing store/encrypted PEM or DER key password")
	cmd.Flags().StringVar(&keyPassFile, "key-pass-file", "", "File containing a separate JKS private-key password")
	cmd.MarkFlagsMutuallyExclusive("pass-env", "pass-file")
	cmd.MarkFlagsMutuallyExclusive("key-pass-env", "key-pass-file")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Print structured JSON containing metadata only")
	cmd.Flags().StringVar(&colorMode, "color", "auto", "ANSI colors: auto, always or never (JSON is always plain)")
	cmd.Flags().IntVar(&expiryDays, "expiry-warning-days", 30, "Warn when certificates expire within this many days; 0 disables the warning")
	return cmd
}

func inspectContents(data []byte, pass, keyPass *inspectPassword) (*inspectionReport, error) {
	report := &inspectionReport{Integrity: "not applicable", Entries: []inspectionEntry{}}
	trimmed := bytes.TrimSpace(bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf}))
	switch {
	case bytes.HasPrefix(data, []byte{0xfe, 0xed, 0xfe, 0xed}):
		report.Format = "JKS"
		if err := inspectJKS(data, report, pass, keyPass); err != nil {
			return nil, err
		}
	case bytes.HasPrefix(trimmed, []byte("-----BEGIN ")):
		report.Format = "PEM"
		if err := inspectPEM(trimmed, report, pass); err != nil {
			return nil, err
		}
	case pkcs12.IsPFX(data):
		report.Format = "PKCS#12"
		pw := ""
		if pass.provided() {
			var err error
			pw, err = pass.read("PFX password: ", false)
			if err != nil {
				return nil, err
			}
		}
		info, err := pkcs12.Inspect(data, pw)
		if err != nil && !pass.provided() && (errors.Is(err, pkcs12.ErrIncorrectPassword) || errors.Is(err, pkcs12.ErrDecryption)) {
			pw, err = pass.read("PFX password: ", false)
			if err != nil {
				return nil, err
			}
			info, err = pkcs12.Inspect(data, pw)
		}
		if err != nil {
			return nil, fmt.Errorf("inspect PFX: %w", err)
		}
		report.StoreVersion, report.Integrity, report.MAC, report.Encryption = info.Version, info.Integrity, info.MAC, info.Encryption
		for _, object := range info.Entries {
			entry := inspectionEntry{Type: object.Type, Alias: object.Alias, LocalKeyID: object.LocalKeyID, Protection: object.Protection}
			if object.Certificate != nil {
				if err := addCertificate(report, entry, object.Certificate); err != nil {
					return nil, err
				}
			} else if object.PrivateKey != nil {
				if err := addPrivateKey(report, entry, object.PrivateKey); err != nil {
					return nil, err
				}
			} else {
				report.Entries = append(report.Entries, entry)
			}
		}
	default:
		report.Format = "DER"
		if certs, err := x509.ParseCertificates(data); err == nil && len(certs) > 0 {
			for _, cert := range certs {
				if err := addCertificate(report, inspectionEntry{Type: "certificate"}, cert); err != nil {
					return nil, err
				}
			}
		} else if key, err := parsePrivateKey(data); err == nil {
			if err := addPrivateKey(report, inspectionEntry{Type: "private key"}, key); err != nil {
				return nil, err
			}
		} else if key, err := parsePublicKey(data); err == nil {
			if err := addPublicKey(report, inspectionEntry{Type: "public key"}, key); err != nil {
				return nil, err
			}
		} else if protection, err := pkcs12.EncryptedKeyProtection(data); err == nil {
			key, err := decryptPKCS8(data, pass, "Encrypted DER key password: ")
			if err != nil {
				return nil, err
			}
			if err := addPrivateKey(report, inspectionEntry{Type: "private key", Protection: &protection}, key); err != nil {
				return nil, err
			}
		} else {
			return nil, errors.New("unrecognized or unsupported file content (expected PFX, JKS, PEM or DER certificate/key)")
		}
	}
	report.EntryCount = len(report.Entries)
	for i := range report.Entries {
		report.Entries[i].ID = fmt.Sprintf("entry-%d", i+1)
		switch report.Entries[i].Type {
		case "certificate", "trusted certificate":
			report.CertificateCount++
		case "private key":
			report.PrivateKeyCount++
		case "public key":
			report.PublicKeyCount++
		}
	}
	// Match by canonical SPKI fingerprint, not only alias/localKeyId metadata.
	for i := range report.Entries {
		entry := &report.Entries[i]
		if entry.PublicKey == nil {
			continue
		}
		for j := range report.Entries {
			other := report.Entries[j]
			if i != j && other.PublicKey != nil && other.PublicKey.SHA256 == entry.PublicKey.SHA256 && (entry.Certificate != nil) != (other.Certificate != nil) {
				entry.Matches = append(entry.Matches, other.ID)
			}
		}
	}
	applyExpiryStatus(report, time.Now(), 30)
	return report, nil
}

func inspectJKS(data []byte, report *inspectionReport, pass, keyPass *inspectPassword) error {
	load := func(pw string) (keystore.KeyStore, error) {
		ks := keystore.New(keystore.WithCaseExactAliases())
		err := ks.Load(bytes.NewReader(data), []byte(pw))
		return ks, err
	}
	pw := ""
	if pass.provided() {
		var err error
		pw, err = pass.read("JKS store password: ", false)
		if err != nil {
			return err
		}
	}
	ks, err := load(pw)
	if err != nil && !pass.provided() && strings.Contains(err.Error(), "invalid digest") {
		pw, err = pass.read("JKS store password: ", false)
		if err != nil {
			return err
		}
		ks, err = load(pw)
	}
	if err != nil {
		return fmt.Errorf("inspect JKS (password or integrity): %w", err)
	}
	report.Integrity = "verified"
	report.MAC = &pkcs12.Protection{Algorithm: "SHA-1"}
	if len(data) >= 8 {
		report.StoreVersion = int(binary.BigEndian.Uint32(data[4:8]))
	}
	aliases := ks.Aliases()
	sort.Strings(aliases)
	for _, alias := range aliases {
		if ks.IsTrustedCertificateEntry(alias) {
			entry, err := ks.GetTrustedCertificateEntry(alias)
			if err != nil {
				return err
			}
			cert, err := x509.ParseCertificate(entry.Certificate.Content)
			if err != nil {
				return err
			}
			created := entry.CreationTime
			if err := addCertificate(report, inspectionEntry{Type: "trusted certificate", Alias: alias, Created: &created}, cert); err != nil {
				return err
			}
			continue
		}
		if !ks.IsPrivateKeyEntry(alias) {
			return fmt.Errorf("unsupported JKS entry %q", alias)
		}
		entry, err := ks.GetPrivateKeyEntry(alias, []byte(pw))
		if err != nil {
			var keyPW string
			if keyPass.provided() {
				keyPW, err = keyPass.read("", false)
			} else {
				keyPW, err = keyPass.read(fmt.Sprintf("Private key %q password: ", alias), true)
			}
			if err != nil {
				return err
			}
			entry, err = ks.GetPrivateKeyEntry(alias, []byte(keyPW))
		}
		if err != nil {
			return fmt.Errorf("decrypt JKS private key %q: %w", alias, err)
		}
		key, err := parsePrivateKey(entry.PrivateKey)
		if err != nil {
			return err
		}
		created := entry.CreationTime
		protection := &pkcs12.Protection{Algorithm: "JKS KeyProtector", OID: "1.3.6.1.4.1.42.2.17.1.1"}
		if err := addPrivateKey(report, inspectionEntry{Type: "private key", Alias: alias, Created: &created, Protection: protection}, key); err != nil {
			return err
		}
		for _, item := range entry.CertificateChain {
			cert, err := x509.ParseCertificate(item.Content)
			if err != nil {
				return err
			}
			if err := addCertificate(report, inspectionEntry{Type: "certificate", Alias: alias}, cert); err != nil {
				return err
			}
		}
	}
	return nil
}

func inspectPEM(data []byte, report *inspectionReport, pass *inspectPassword) error {
	for len(bytes.TrimSpace(data)) > 0 {
		data = bytes.TrimSpace(data)
		if !bytes.HasPrefix(data, []byte("-----BEGIN ")) {
			return errors.New("unexpected text outside PEM blocks")
		}
		lineEnd := bytes.IndexByte(data, '\n')
		if lineEnd < 0 {
			return errors.New("truncated PEM header")
		}
		header := strings.TrimSpace(string(data[:lineEnd]))
		if !strings.HasSuffix(header, "-----") {
			return errors.New("invalid PEM header")
		}
		blockType := strings.TrimSuffix(strings.TrimPrefix(header, "-----BEGIN "), "-----")
		endMarker := []byte("-----END " + blockType + "-----")
		end := bytes.Index(data, endMarker)
		if end < 0 {
			return errors.New("missing PEM end marker")
		}
		end += len(endMarker)
		block, trailing := pem.Decode(data[:end])
		if block == nil || len(bytes.TrimSpace(trailing)) != 0 {
			return errors.New("invalid PEM block")
		}
		data = data[end:]
		der := block.Bytes
		entry := inspectionEntry{}
		if x509.IsEncryptedPEMBlock(block) {
			decrypt := func(pw string) ([]byte, error) {
				decrypted, err := x509.DecryptPEMBlock(block, []byte(pw))
				if err != nil {
					return nil, err
				}
				// Legacy PEM has no authentication: valid padding alone does
				// not prove that the empty/cached password was correct.
				switch block.Type {
				case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
					if _, err := parsePrivateKey(decrypted); err != nil {
						return nil, err
					}
				case "CERTIFICATE", "X509 CERTIFICATE":
					if _, err := x509.ParseCertificates(decrypted); err != nil {
						return nil, err
					}
				case "PUBLIC KEY", "RSA PUBLIC KEY":
					if _, err := parsePublicKey(decrypted); err != nil {
						return nil, err
					}
				}
				return decrypted, nil
			}
			pw := ""
			if pass.set {
				pw = pass.value
			}
			var err error
			if pass.provided() {
				pw, err = pass.read("PEM key password: ", false)
				if err != nil {
					return err
				}
			}
			der, err = decrypt(pw)
			if err != nil && !pass.provided() {
				pw, err = pass.read("PEM key password: ", true)
				if err != nil {
					return err
				}
				der, err = decrypt(pw)
			}
			if err != nil {
				return fmt.Errorf("decrypt PEM: %w", err)
			}
			cipherName := strings.Split(block.Headers["DEK-Info"], ",")[0]
			entry.Protection = &pkcs12.Protection{Algorithm: "legacy PEM", Cipher: cipherName}
		}
		switch block.Type {
		case "CERTIFICATE", "X509 CERTIFICATE":
			certs, err := x509.ParseCertificates(der)
			if err != nil {
				return fmt.Errorf("parse PEM certificate: %w", err)
			}
			for _, cert := range certs {
				entry.Type = "certificate"
				if err := addCertificate(report, entry, cert); err != nil {
					return err
				}
			}
		case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
			key, err := parsePrivateKey(der)
			if err != nil {
				return fmt.Errorf("parse PEM private key: %w", err)
			}
			entry.Type = "private key"
			if err := addPrivateKey(report, entry, key); err != nil {
				return err
			}
		case "ENCRYPTED PRIVATE KEY":
			protection, err := pkcs12.EncryptedKeyProtection(der)
			if err != nil {
				return err
			}
			key, err := decryptPKCS8(der, pass, "PKCS#8 key password: ")
			if err != nil {
				return err
			}
			entry.Type, entry.Protection = "private key", &protection
			if err := addPrivateKey(report, entry, key); err != nil {
				return err
			}
		case "PUBLIC KEY", "RSA PUBLIC KEY":
			key, err := parsePublicKey(der)
			if err != nil {
				return err
			}
			entry.Type = "public key"
			if err := addPublicKey(report, entry, key); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported PEM object type %q", block.Type)
		}
	}
	if len(report.Entries) == 0 {
		return errors.New("PEM contains no supported objects")
	}
	return nil
}

func decryptPKCS8(data []byte, pass *inspectPassword, prompt string) (any, error) {
	pw := ""
	if pass.set {
		pw = pass.value
	}
	if pass.provided() {
		var err error
		pw, err = pass.read(prompt, false)
		if err != nil {
			return nil, err
		}
	}
	key, err := pkcs12.ParseEncryptedPrivateKey(data, pw)
	if err != nil && !pass.provided() {
		pw, err = pass.read(prompt, true)
		if err != nil {
			return nil, err
		}
		key, err = pkcs12.ParseEncryptedPrivateKey(data, pw)
	}
	if err != nil {
		return nil, fmt.Errorf("decrypt encrypted PKCS#8 key: %w", err)
	}
	return key, nil
}

func parsePrivateKey(der []byte) (any, error) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, errors.New("unsupported or malformed private key")
}
func parsePublicKey(der []byte) (any, error) {
	if key, err := x509.ParsePKIXPublicKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PublicKey(der); err == nil {
		return key, nil
	}
	return nil, errors.New("unsupported or malformed public key")
}

func keyDetails(key any) (*publicKeyDetails, error) {
	detail := &publicKeyDetails{}
	switch key := key.(type) {
	case *rsa.PublicKey:
		detail.Algorithm = "RSA"
		detail.Bits = key.N.BitLen()
	case *ecdsa.PublicKey:
		detail.Algorithm = "ECDSA"
		detail.Bits = key.Curve.Params().BitSize
		detail.Curve = key.Curve.Params().Name
	case ed25519.PublicKey:
		detail.Algorithm = "Ed25519"
		detail.Bits = 256
	case *dsa.PublicKey:
		detail.Algorithm = "DSA"
		detail.Bits = key.P.BitLen()
	default:
		detail.Algorithm = fmt.Sprintf("%T", key)
	}
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}
	detail.SHA256 = fmt.Sprintf("%x", sha256.Sum256(der))
	return detail, nil
}
func addPublicKey(report *inspectionReport, entry inspectionEntry, key any) error {
	info, err := keyDetails(key)
	if err != nil {
		return err
	}
	entry.PublicKey = info
	report.Entries = append(report.Entries, entry)
	return nil
}
func addPrivateKey(report *inspectionReport, entry inspectionEntry, key any) error {
	signer, ok := key.(crypto.Signer)
	if !ok {
		return fmt.Errorf("unsupported private key type %T", key)
	}
	return addPublicKey(report, entry, signer.Public())
}
func addCertificate(report *inspectionReport, entry inspectionEntry, cert *x509.Certificate) error {
	info, err := keyDetails(cert.PublicKey)
	if err != nil {
		return err
	}
	entry.PublicKey = info
	detail := &certificateDetails{Subject: cert.Subject.String(), Issuer: cert.Issuer.String(), Serial: strings.ToUpper(cert.SerialNumber.Text(16)), Version: cert.Version, NotBefore: cert.NotBefore, NotAfter: cert.NotAfter, SignatureAlgorithm: cert.SignatureAlgorithm.String(), SHA256: fmt.Sprintf("%x", sha256.Sum256(cert.Raw)), IsCA: cert.IsCA, BasicConstraintsValid: cert.BasicConstraintsValid, KeyUsage: []string{}, ExtendedKeyUsage: []string{}, SAN: []string{}}
	if cert.MaxPathLenZero || cert.MaxPathLen > 0 {
		length := cert.MaxPathLen
		detail.MaxPathLen = &length
	}
	detail.SelfSigned = bytes.Equal(cert.RawSubject, cert.RawIssuer) && cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
	names := []struct {
		flag x509.KeyUsage
		name string
	}{
		{x509.KeyUsageDigitalSignature, "digital signature"}, {x509.KeyUsageContentCommitment, "content commitment"}, {x509.KeyUsageKeyEncipherment, "key encipherment"}, {x509.KeyUsageDataEncipherment, "data encipherment"}, {x509.KeyUsageKeyAgreement, "key agreement"}, {x509.KeyUsageCertSign, "certificate sign"}, {x509.KeyUsageCRLSign, "CRL sign"}, {x509.KeyUsageEncipherOnly, "encipher only"}, {x509.KeyUsageDecipherOnly, "decipher only"},
	}
	for _, name := range names {
		if cert.KeyUsage&name.flag != 0 {
			detail.KeyUsage = append(detail.KeyUsage, name.name)
		}
	}
	eku := map[x509.ExtKeyUsage]string{x509.ExtKeyUsageAny: "any", x509.ExtKeyUsageServerAuth: "server auth", x509.ExtKeyUsageClientAuth: "client auth", x509.ExtKeyUsageCodeSigning: "code signing", x509.ExtKeyUsageEmailProtection: "email protection", x509.ExtKeyUsageTimeStamping: "time stamping", x509.ExtKeyUsageOCSPSigning: "OCSP signing", x509.ExtKeyUsageIPSECEndSystem: "IPsec end system", x509.ExtKeyUsageIPSECTunnel: "IPsec tunnel", x509.ExtKeyUsageIPSECUser: "IPsec user", x509.ExtKeyUsageMicrosoftServerGatedCrypto: "Microsoft SGC", x509.ExtKeyUsageNetscapeServerGatedCrypto: "Netscape SGC", x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "Microsoft commercial code signing", x509.ExtKeyUsageMicrosoftKernelCodeSigning: "Microsoft kernel code signing"}
	for _, usage := range cert.ExtKeyUsage {
		name := eku[usage]
		if name == "" {
			name = fmt.Sprintf("usage %d", usage)
		}
		detail.ExtendedKeyUsage = append(detail.ExtendedKeyUsage, name)
	}
	for _, oid := range cert.UnknownExtKeyUsage {
		detail.ExtendedKeyUsage = append(detail.ExtendedKeyUsage, oid.String())
	}
	for _, name := range cert.DNSNames {
		detail.SAN = append(detail.SAN, "DNS:"+name)
	}
	for _, name := range cert.EmailAddresses {
		detail.SAN = append(detail.SAN, "email:"+name)
	}
	for _, ip := range cert.IPAddresses {
		detail.SAN = append(detail.SAN, "IP:"+ip.String())
	}
	for _, uri := range cert.URIs {
		detail.SAN = append(detail.SAN, "URI:"+uri.String())
	}
	for _, oid := range cert.UnhandledCriticalExtensions {
		detail.UnhandledCriticalExtensions = append(detail.UnhandledCriticalExtensions, oid.String())
	}
	entry.Certificate = detail
	report.Entries = append(report.Entries, entry)
	return nil
}

func protectionText(p pkcs12.Protection) string {
	values := []string{p.Algorithm}
	if p.Cipher != "" {
		values = append(values, p.Cipher)
	}
	if p.KDF != "" {
		values = append(values, p.KDF)
	}
	if p.PRF != "" {
		values = append(values, p.PRF)
	}
	if p.Iterations > 0 {
		values = append(values, fmt.Sprintf("%d iterations", p.Iterations))
	}
	if p.OID != "" {
		values = append(values, "OID "+p.OID)
	}
	return strings.Join(values, "; ")
}
