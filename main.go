package main

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
	"golang.org/x/term"
	"software.sslmate.com/src/go-pkcs12"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "ssl-toolbox:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	cmd := newRootCommand(stdout, stderr)
	cmd.SetArgs(legacyArgs(args))
	return cmd.Execute()
}

type conversionOptions struct {
	in, out, format, alias, inEnv, outEnv string
	inPassFile, outPassFile               string
	caFiles                               []string
}

// Preserve the original Go flag syntax (-in) while Cobra uses --in. Only
// normalize known flag tokens; values and tokens following -- stay untouched.
func legacyArgs(args []string) []string {
	result := append([]string(nil), args...)
	for i := 0; i < len(result); i++ {
		if result[i] == "--" {
			break
		}
		name, _, hasValue := strings.Cut(result[i], "=")
		switch name {
		case "-in", "-out", "-format", "-alias", "-in-pass-env", "-out-pass-env", "-in-pass-file", "-out-pass-file", "-add-ca":
			result[i] = "-" + result[i]
		case "--in", "--out", "--format", "--alias", "--in-pass-env", "--out-pass-env", "--in-pass-file", "--out-pass-file", "--add-ca":
		default:
			continue
		}
		if !hasValue {
			i++ // Next token is a value, even if it looks like a flag.
		}
	}
	return result
}

func convertFile(options conversionOptions, stdout, stderr io.Writer) error {
	in, out := &options.in, &options.out
	format, alias := &options.format, &options.alias
	inEnv, outEnv := &options.inEnv, &options.outEnv
	if err := validatePasswordSource(*inEnv, options.inPassFile); err != nil {
		return err
	}
	if err := validatePasswordSource(*outEnv, options.outPassFile); err != nil {
		return err
	}
	if *out == "" || (*in == "" && len(options.caFiles) == 0) {
		return errors.New("specify --out and at least one of --in or --add-ca")
	}
	*format = strings.ToLower(*format)
	if *format != "pfx" && *format != "jks" {
		return errors.New("--format must be pfx or jks")
	}
	if *format == "jks" && strings.TrimSpace(*alias) == "" {
		return errors.New("JKS alias must not be empty")
	}
	if _, err := os.Lstat(*out); err == nil {
		return fmt.Errorf("output %q already exists", *out)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("check output: %w", err)
	}
	addedCAs, err := readCAs(options.caFiles)
	if err != nil {
		return err
	}
	var data []byte
	var oldPassword string
	if *in != "" {
		data, err = os.ReadFile(*in)
		if err != nil {
			return fmt.Errorf("read input: %w", err)
		}
		if len(data) == 0 {
			return errors.New("input PFX is empty")
		}
		oldPassword, err = readPasswordSource(*inEnv, options.inPassFile, "Input PFX password: ", stderr)
		if err != nil {
			return err
		}
	}
	newPassword, err := readPasswordSource(*outEnv, options.outPassFile, "New keystore/key password: ", stderr)
	if err != nil {
		return err
	}
	if newPassword == "" {
		return errors.New("new password must not be empty")
	}
	if *outEnv == "" && options.outPassFile == "" {
		confirmation, err := password("", "Confirm new password: ", stderr)
		if err != nil {
			return err
		}
		if confirmation != newPassword {
			return errors.New("new passwords do not match")
		}
	}
	converted, err := convertWithCAs(data, oldPassword, newPassword, *format, *alias, addedCAs)
	if err != nil {
		return err
	}
	if err := writeNewFile(*out, converted); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Created %s (%s; added %d trusted CA certificates).\n", *out, strings.ToUpper(*format), len(addedCAs))
	return nil
}

func password(env, prompt string, stderr io.Writer) (string, error) {
	return readPasswordSource(env, "", prompt, stderr)
}

func validatePasswordSource(env, file string) error {
	if env != "" && file != "" {
		return errors.New("choose one password source: ENV or FILE, not both")
	}
	return nil
}

func readPasswordSource(env, file, prompt string, stderr io.Writer) (string, error) {
	if err := validatePasswordSource(env, file); err != nil {
		return "", err
	}
	if file != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			return "", fmt.Errorf("read password file: %w", err)
		}
		value := string(data)
		// Ignore one line ending added by text editors/echo; preserve all spaces.
		if strings.HasSuffix(value, "\n") {
			value = strings.TrimSuffix(value, "\n")
			value = strings.TrimSuffix(value, "\r")
		}
		return value, nil
	}
	if env != "" {
		value, ok := os.LookupEnv(env)
		if !ok {
			return "", fmt.Errorf("password environment variable %q is not set", env)
		}
		return value, nil
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", errors.New("password required without a terminal; supply an ENV or FILE password source (see command --help)")
	}
	fmt.Fprint(stderr, prompt)
	value, err := term.ReadPassword(fd)
	fmt.Fprintln(stderr)
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	return string(value), nil
}

func repack(data []byte, oldPassword, newPassword string) ([]byte, error) {
	return convert(data, oldPassword, newPassword, "pfx", "client")
}

func convert(data []byte, oldPassword, newPassword, format, alias string) ([]byte, error) {
	return convertWithCAs(data, oldPassword, newPassword, format, alias, nil)
}

func convertWithCAs(data []byte, oldPassword, newPassword, format, alias string, added []*x509.Certificate) ([]byte, error) {
	var key any
	var cert *x509.Certificate
	var chain []*x509.Certificate
	var trusted []pkcs12.TrustStoreEntry
	if len(data) > 0 {
		var err error
		key, cert, chain, trusted, err = pkcs12.DecodeWithTrust(data, oldPassword)
		if err != nil {
			return nil, fmt.Errorf("decode input PFX (check password and format): %w", err)
		}
	}
	for _, ca := range added {
		trusted = append(trusted, pkcs12.TrustStoreEntry{Cert: ca})
	}
	trusted = uniqueTrustEntries(trusted)
	if key == nil && len(trusted) == 0 {
		return nil, errors.New("no private identity or trusted CA certificates to export")
	}
	if key != nil {
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, errors.New("unsupported private key type")
		}
		keyPublic, err := x509.MarshalPKIXPublicKey(signer.Public())
		if err != nil {
			return nil, fmt.Errorf("read key public part: %w", err)
		}
		if cert == nil || !bytes.Equal(keyPublic, cert.RawSubjectPublicKeyInfo) {
			return nil, errors.New("private key does not match client certificate")
		}
	}
	if format == "jks" {
		return encodeJKS(key, cert, chain, trusted, newPassword, alias)
	}
	if format != "pfx" {
		return nil, errors.New("unsupported output format")
	}
	// One password encrypts the key and certificates and authenticates the PFX.
	var result []byte
	var err error
	if key == nil {
		result, err = pkcs12.Modern2023.EncodeTrustStoreEntries(trusted, newPassword)
	} else {
		result, err = pkcs12.Modern2023.EncodeWithTrust(key, cert, chain, trusted, newPassword)
	}
	if err != nil {
		return nil, fmt.Errorf("encode new PFX: %w", err)
	}
	return result, nil
}

func encodeJKS(key any, cert *x509.Certificate, chain []*x509.Certificate, trusted []pkcs12.TrustStoreEntry, password, alias string) ([]byte, error) {
	ks := keystore.New()
	if key != nil {
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("encode JKS private key: %w", err)
		}
		certificates := []keystore.Certificate{{Type: "X509", Content: cert.Raw}}
		for _, ca := range chain {
			certificates = append(certificates, keystore.Certificate{Type: "X509", Content: ca.Raw})
		}
		entry := keystore.PrivateKeyEntry{CreationTime: time.Now(), PrivateKey: keyDER, CertificateChain: certificates}
		if err := ks.SetPrivateKeyEntry(strings.ToLower(alias), entry, []byte(password)); err != nil {
			return nil, fmt.Errorf("create JKS key entry: %w", err)
		}
	}
	for _, ca := range trusted {
		if key != nil && strings.EqualFold(ca.FriendlyName, alias) {
			return nil, errors.New("key alias collides with a CA alias; choose a different --alias")
		}
		entry := keystore.TrustedCertificateEntry{CreationTime: time.Now(), Certificate: keystore.Certificate{Type: "X509", Content: ca.Cert.Raw}}
		if err := ks.SetTrustedCertificateEntry(ca.FriendlyName, entry); err != nil {
			return nil, fmt.Errorf("create JKS trusted entry: %w", err)
		}
	}
	var result bytes.Buffer
	if err := ks.Store(&result, []byte(password)); err != nil {
		return nil, fmt.Errorf("encode JKS: %w", err)
	}
	return result.Bytes(), nil
}

func uniqueTrustEntries(entries []pkcs12.TrustStoreEntry) []pkcs12.TrustStoreEntry {
	seen := make(map[[32]byte]bool)
	var result []pkcs12.TrustStoreEntry
	for _, entry := range entries {
		fingerprint := sha256.Sum256(entry.Cert.Raw)
		if !seen[fingerprint] {
			seen[fingerprint] = true
			entry.FriendlyName = fmt.Sprintf("ca-%x", fingerprint)
			result = append(result, entry)
		}
	}
	return result
}

func readCAs(paths []string) ([]*x509.Certificate, error) {
	var certificates []*x509.Certificate
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read CA %q: %w", path, err)
		}
		count := 0
		for len(bytes.TrimSpace(data)) > 0 {
			data = bytes.TrimSpace(data)
			if !bytes.HasPrefix(data, []byte("-----BEGIN CERTIFICATE-----")) {
				return nil, fmt.Errorf("CA %q: expected CERTIFICATE PEM block", path)
			}
			endMarker := []byte("-----END CERTIFICATE-----")
			end := bytes.Index(data, endMarker)
			if end < 0 {
				return nil, fmt.Errorf("CA %q: missing PEM end marker", path)
			}
			end += len(endMarker)
			block, trailing := pem.Decode(data[:end])
			rest := data[end:]
			if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(trailing)) != 0 {
				return nil, fmt.Errorf("CA %q: invalid CERTIFICATE PEM block", path)
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse CA %q: %w", path, err)
			}
			if !cert.IsCA {
				return nil, fmt.Errorf("CA %q: certificate %q is not a CA", path, cert.Subject.String())
			}
			certificates = append(certificates, cert)
			count++
			data = rest
		}
		if count == 0 {
			return nil, fmt.Errorf("CA %q contains no certificates", path)
		}
	}
	entries := make([]pkcs12.TrustStoreEntry, 0, len(certificates))
	for _, cert := range certificates {
		entries = append(entries, pkcs12.TrustStoreEntry{Cert: cert})
	}
	certificates = nil
	for _, entry := range uniqueTrustEntries(entries) {
		certificates = append(certificates, entry.Cert)
	}
	return certificates, nil
}

func writeNewFile(path string, data []byte) (err error) {
	// O_EXCL also protects against a file appearing after the initial check.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	defer func() {
		if err != nil {
			_ = f.Close()
			_ = os.Remove(path)
		}
	}()
	if _, err = f.Write(data); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	if err = f.Sync(); err != nil {
		return fmt.Errorf("sync output: %w", err)
	}
	if err = f.Close(); err != nil {
		return fmt.Errorf("close output: %w", err)
	}
	return nil
}
