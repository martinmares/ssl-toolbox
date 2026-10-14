package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/spf13/cobra"
)

type csrOptions struct {
	cn, email, country, province, locality, organization, unit string
	outDir, name, keyFile, keyPassEnv, keyPassFile, sansFile   string
	dns, ips                                                   []string
	bits                                                       int
}

func newCSRCommand(stdout, stderr io.Writer) *cobra.Command {
	parent := &cobra.Command{Use: "csr", Short: "Create certificate signing requests", Args: cobra.NoArgs}
	parent.RunE = func(cmd *cobra.Command, args []string) error { return cmd.Help() }
	var o csrOptions
	cmd := &cobra.Command{Use: "create", Short: "Create an RSA/SHA-256 CSR and optionally a new private key", Args: cobra.NoArgs,
		Example: "  ssl-toolbox csr create --cn server.example.org --dns server.example.org --out-dir certificates\n  ssl-toolbox csr create --cn server.example.org --sans-file dns-names.txt --ip 192.0.2.10 --out-dir certificates --name server\n  ssl-toolbox csr create --cn server.example.org --dns server.example.org --key existing.key --out-dir requests",
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			return createCSR(o, stdout, stderr)
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.cn, "cn", "", "Subject common name; default output basename")
	f.StringVar(&o.email, "email", "", "Subject emailAddress (optional; does not add an email SAN)")
	f.StringVar(&o.country, "country", "", "Subject country code, two ASCII letters")
	f.StringVar(&o.province, "province", "", "Subject state or province")
	f.StringVar(&o.locality, "locality", "", "Subject locality or city")
	f.StringVar(&o.organization, "organization", "", "Subject organization")
	f.StringVar(&o.unit, "organizational-unit", "", "Subject organizational unit")
	f.StringVar(&o.outDir, "out-dir", "", "Output directory, created if needed; existing files are never overwritten")
	f.StringVar(&o.name, "name", "", "Output basename without extension; defaults to CN (use an explicit name for wildcard CNs)")
	f.IntVar(&o.bits, "bits", 4096, "New RSA key size: 2048, 3072, 4096 or 8192")
	f.StringVar(&o.keyFile, "key", "", "Reuse an RSA private key in PEM or DER; only the CSR is written")
	f.StringVar(&o.keyPassEnv, "key-pass-env", "", "Environment variable containing the existing encrypted key password")
	f.StringVar(&o.keyPassFile, "key-pass-file", "", "File containing the existing encrypted key password")
	f.StringArrayVar(&o.dns, "dns", nil, "DNS SAN, repeatable; wildcard permitted only as the first label")
	f.StringArrayVar(&o.ips, "ip", nil, "IPv4 or IPv6 SAN, repeatable")
	f.StringVar(&o.sansFile, "sans-file", "", "DNS names, one per line; blank lines and # comments are ignored")
	cmd.MarkFlagsMutuallyExclusive("key", "bits")
	cmd.MarkFlagsMutuallyExclusive("key-pass-env", "key-pass-file")
	_ = cmd.MarkFlagRequired("cn")
	_ = cmd.MarkFlagRequired("out-dir")
	parent.AddCommand(cmd, newCSRBatchCommand(stdout, stderr))
	return parent
}

type csrPlan struct {
	options          csrOptions
	template         *x509.CertificateRequest
	key              *rsa.PrivateKey
	csrPath, keyPath string
}

func createCSR(o csrOptions, stdout, stderr io.Writer) error {
	plan, err := prepareCSR(o, stderr)
	if err != nil {
		return err
	}
	if err := writeCSR(plan); err != nil {
		return err
	}
	return printCSRCreated(plan, stdout)
}

func prepareCSR(o csrOptions, stderr io.Writer) (*csrPlan, error) {
	for _, value := range []string{o.cn, o.email, o.country, o.province, o.locality, o.organization, o.unit} {
		if strings.IndexFunc(value, unicode.IsControl) >= 0 {
			return nil, errors.New("subject fields must not contain control characters")
		}
	}
	if strings.TrimSpace(o.cn) == "" || strings.TrimSpace(o.outDir) == "" {
		return nil, errors.New("--cn and --out-dir must not be empty")
	}
	if o.name == "" {
		o.name = o.cn
	}
	if o.name == "." || o.name == ".." || strings.TrimSpace(o.name) != o.name || strings.HasSuffix(o.name, ".") || strings.ContainsAny(o.name, `/\:*?"<>|`) || strings.IndexFunc(o.name, unicode.IsControl) >= 0 {
		return nil, errors.New("--name must be a filename basename, not a path; use --name for a wildcard CN")
	}
	if o.country != "" {
		if len(o.country) != 2 || strings.IndexFunc(o.country, func(r rune) bool { return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') }) >= 0 {
			return nil, errors.New("--country must contain two ASCII letters")
		}
		o.country = strings.ToUpper(o.country)
	}
	if o.email != "" {
		address, err := mail.ParseAddress(o.email)
		if err != nil || address.Address != o.email || strings.IndexFunc(o.email, func(r rune) bool { return r > 127 }) >= 0 {
			return nil, errors.New("--email must be a plain ASCII email address")
		}
	}
	if o.keyFile == "" && (o.keyPassEnv != "" || o.keyPassFile != "") {
		return nil, errors.New("key password options require --key")
	}
	if o.bits != 2048 && o.bits != 3072 && o.bits != 4096 && o.bits != 8192 {
		return nil, errors.New("--bits must be 2048, 3072, 4096 or 8192")
	}
	dns, ips, err := csrAlternativeNames(o)
	if err != nil {
		return nil, err
	}
	csrPath := filepath.Join(o.outDir, o.name+".csr")
	keyPath := filepath.Join(o.outDir, o.name+".key")
	paths := []string{csrPath}
	if o.keyFile == "" {
		paths = append(paths, keyPath)
	}
	for _, path := range paths {
		if _, err := os.Lstat(path); err == nil {
			return nil, fmt.Errorf("output %q already exists", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("check output: %w", err)
		}
	}
	var key *rsa.PrivateKey
	if o.keyFile != "" {
		key, err = readCSRKey(o.keyFile, &inspectPassword{env: o.keyPassEnv, file: o.keyPassFile, stderr: stderr})
		if err != nil {
			return nil, fmt.Errorf("prepare RSA key: %w", err)
		}
	}

	subject := pkix.Name{CommonName: o.cn}
	for _, item := range []struct {
		value string
		dest  *[]string
	}{{o.country, &subject.Country}, {o.province, &subject.Province}, {o.locality, &subject.Locality}, {o.organization, &subject.Organization}, {o.unit, &subject.OrganizationalUnit}} {
		if item.value != "" {
			*item.dest = []string{item.value}
		}
	}
	if o.email != "" {
		subject.ExtraNames = []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}, Value: asn1.RawValue{Tag: asn1.TagIA5String, Bytes: []byte(o.email)}}}
	}
	template := &x509.CertificateRequest{Subject: subject, DNSNames: dns, IPAddresses: ips, SignatureAlgorithm: x509.SHA256WithRSA}
	if _, err := asn1.Marshal(subject.ToRDNSequence()); err != nil {
		return nil, fmt.Errorf("encode CSR subject: %w", err)
	}
	return &csrPlan{options: o, template: template, key: key, csrPath: csrPath, keyPath: keyPath}, nil
}

func writeCSR(plan *csrPlan) error {
	o, csrPath, keyPath := plan.options, plan.csrPath, plan.keyPath
	if plan.key == nil {
		key, err := rsa.GenerateKey(rand.Reader, o.bits)
		if err != nil {
			return fmt.Errorf("generate RSA key: %w", err)
		}
		plan.key = key
	}
	key := plan.key

	der, err := x509.CreateCertificateRequest(rand.Reader, plan.template, key)
	if err != nil {
		return fmt.Errorf("create CSR: %w", err)
	}
	if err := os.MkdirAll(o.outDir, 0700); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	if o.keyFile == "" {
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return err
		}
		if err := writeNewFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})); err != nil {
			return err
		}
	}
	if err := writeNewFile(csrPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})); err != nil {
		if o.keyFile == "" {
			err = errors.Join(err, os.Remove(keyPath))
		}
		return err
	}
	return nil
}

func printCSRCreated(plan *csrPlan, stdout io.Writer) error {
	o, key, csrPath, keyPath := plan.options, plan.key, plan.csrPath, plan.keyPath
	if o.keyFile == "" {
		if _, err := fmt.Fprintf(stdout, "Created %s (unencrypted RSA %d-bit PKCS#8 key)\n", keyPath, key.N.BitLen()); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(stdout, "Created %s (SHA-256 CSR; DNS SANs: %d; IP SANs: %d)\n", csrPath, len(plan.template.DNSNames), len(plan.template.IPAddresses))
	return err
}

func csrAlternativeNames(o csrOptions) ([]string, []net.IP, error) {
	names := append([]string{}, o.dns...)
	if o.sansFile != "" {
		file, err := os.Open(o.sansFile)
		if err != nil {
			return nil, nil, fmt.Errorf("read SAN file: %w", err)
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line, _, _ := strings.Cut(scanner.Text(), "#")
			if line = strings.TrimSpace(line); line != "" {
				names = append(names, line)
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, nil, fmt.Errorf("read SAN file: %w", err)
		}
	}
	dns := []string{}
	ips := []net.IP{}
	seen := map[string]bool{}
	for _, name := range names {
		name = strings.ToLower(strings.TrimSuffix(name, "."))
		if len(name) == 0 || len(name) > 253 || net.ParseIP(name) != nil {
			return nil, nil, fmt.Errorf("invalid DNS SAN %q; IP addresses belong in --ip", name)
		}
		for i, label := range strings.Split(name, ".") {
			if i == 0 && label == "*" && strings.Contains(name, ".") {
				continue
			}
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' || strings.IndexFunc(label, func(r rune) bool { return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') }) >= 0 {
				return nil, nil, fmt.Errorf("invalid DNS SAN %q (use ASCII or punycode)", name)
			}
		}
		if !seen["DNS:"+name] {
			dns = append(dns, name)
			seen["DNS:"+name] = true
		}
	}
	for _, value := range o.ips {
		ip := net.ParseIP(value)
		if ip == nil {
			return nil, nil, fmt.Errorf("invalid IP SAN %q", value)
		}
		if !seen["IP:"+ip.String()] {
			ips = append(ips, ip)
			seen["IP:"+ip.String()] = true
		}
	}
	return dns, ips, nil
}

func readCSRKey(path string, pass *inspectPassword) (*rsa.PrivateKey, error) {
	key, err := readPrivateKeyFile(path, pass)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok || rsaKey.N.BitLen() < 2048 {
		return nil, errors.New("--key must be an RSA private key with at least 2048 bits")
	}
	if err := rsaKey.Validate(); err != nil {
		return nil, err
	}
	return rsaKey, nil
}

func readPrivateKeyFile(path string, pass *inspectPassword) (any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var key any
	if bytes.HasPrefix(bytes.TrimSpace(data), []byte("-----BEGIN ")) {
		block, rest := pem.Decode(bytes.TrimSpace(data))
		if block == nil || len(bytes.TrimSpace(rest)) != 0 {
			return nil, errors.New("--key must contain exactly one private key PEM block")
		}
		switch block.Type {
		case "ENCRYPTED PRIVATE KEY":
			key, err = decryptPKCS8(block.Bytes, pass, "RSA key password: ")
		case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
			der := block.Bytes
			if x509.IsEncryptedPEMBlock(block) {
				var pw string
				pw, err = pass.read("Private key password: ", false)
				if err == nil {
					der, err = x509.DecryptPEMBlock(block, []byte(pw))
				}
			}
			if err == nil {
				key, err = parsePrivateKey(der)
			}
		default:
			return nil, errors.New("--key must be a supported private key")
		}
	} else {
		key, err = parsePrivateKey(data)
		if err != nil {
			key, err = decryptPKCS8(data, pass, "RSA key password: ")
		}
	}
	if err != nil {
		return nil, err
	}
	return key, nil
}
