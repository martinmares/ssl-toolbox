package main

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"software.sslmate.com/src/go-pkcs12"
)

func newExtractCommand(stdout, stderr io.Writer) *cobra.Command {
	var outDir, passEnv, passFile, entryID, certID string
	cmd := &cobra.Command{
		Use: "extract <file.pfx>", Short: "Extract a PFX identity into PEM certificate, unencrypted PKCS#8 key and CA chain files",
		Args:    cobra.ExactArgs(1),
		Example: "  ssl-toolbox extract client.pfx --out-dir ./export\n  ssl-toolbox extract client.pfx --out-dir ./export --pass-file pfx-password\n  ssl-toolbox extract identities.pfx --out-dir ./export --entry entry-3",
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			if strings.TrimSpace(outDir) == "" {
				return errors.New("specify a nonempty --out-dir")
			}
			data, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("read input PFX: %w", err)
			}
			pass := &inspectPassword{env: passEnv, file: passFile, stderr: stderr}
			pw := ""
			if pass.provided() {
				pw, err = pass.read("PFX password: ", false)
				if err != nil {
					return err
				}
			}
			info, err := pkcs12.Inspect(data, pw)
			if err != nil && !pass.provided() && (errors.Is(err, pkcs12.ErrIncorrectPassword) || errors.Is(err, pkcs12.ErrDecryption)) {
				pw, err = pass.read("PFX password: ", false)
				if err != nil {
					return err
				}
				info, err = pkcs12.Inspect(data, pw)
			}
			if err != nil {
				return fmt.Errorf("decode input PFX (check password and format): %w", err)
			}
			key, cert, err := selectPFXIdentity(info, entryID, certID)
			if err != nil {
				return err
			}
			chain, err := extractPFXChain(cert, info)
			if err != nil {
				return err
			}
			der, err := x509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				return fmt.Errorf("encode private key: %w", err)
			}
			base := filepath.Base(args[0])
			base = strings.TrimSuffix(base, filepath.Ext(base))
			if base == "" || base == "." || base == ".." {
				return errors.New("input filename must have a nonempty base name")
			}
			type outputFile struct {
				name string
				data []byte
			}
			files := []outputFile{
				{name: filepath.Join(outDir, base+".key"), data: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})},
				{name: filepath.Join(outDir, base+".pem"), data: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})},
			}
			if len(chain) > 0 {
				files = append(files, outputFile{name: filepath.Join(outDir, base+".chain.pem"), data: chain})
			}
			// Check every destination before writing any private material.
			for _, file := range files {
				if _, err := os.Lstat(file.name); err == nil {
					return fmt.Errorf("output %q already exists", file.name)
				} else if !errors.Is(err, os.ErrNotExist) {
					return fmt.Errorf("check output: %w", err)
				}
			}
			if err := os.MkdirAll(outDir, 0700); err != nil {
				return fmt.Errorf("create output directory: %w", err)
			}
			for i, file := range files {
				if err := writeNewFile(file.name, file.data); err != nil {
					for _, created := range files[:i] {
						err = errors.Join(err, os.Remove(created.name))
					}
					return err
				}
			}
			for _, file := range files {
				if _, err := fmt.Fprintf(stdout, "Created %s\n", file.name); err != nil {
					return err
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&outDir, "out-dir", "", "Output directory (created if needed); existing files are never overwritten")
	cmd.Flags().StringVar(&passEnv, "pass-env", "", "Environment variable with PFX password; otherwise prompt if needed")
	cmd.Flags().StringVar(&passFile, "pass-file", "", "File containing PFX password")
	cmd.MarkFlagsMutuallyExclusive("pass-env", "pass-file")
	cmd.Flags().StringVar(&entryID, "entry", "", "Private key entry ID from inspect (required for multiple keys)")
	cmd.Flags().StringVar(&certID, "cert-entry", "", "Matching certificate entry ID from inspect (required if multiple certificates match)")
	_ = cmd.MarkFlagRequired("out-dir")
	return cmd
}

func selectPFXIdentity(info *pkcs12.Inspection, entryID, certID string) (any, *x509.Certificate, error) {
	var keys []pkcs12.InspectionEntry
	for i, entry := range info.Entries {
		if entry.PrivateKey == nil && entry.Certificate == nil {
			return nil, nil, fmt.Errorf("cannot extract %s", entry.Type)
		}
		if entry.PrivateKey != nil && (entryID == "" || entryID == fmt.Sprintf("entry-%d", i+1)) {
			keys = append(keys, entry)
		}
	}
	if len(keys) != 1 {
		return nil, nil, fmt.Errorf("selection contains %d private keys; use inspect and select one with --entry entry-N", len(keys))
	}
	key := keys[0].PrivateKey
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, nil, errors.New("unsupported private key type")
	}
	public, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, nil, err
	}
	var certs []*x509.Certificate
	for i, entry := range info.Entries {
		cert := entry.Certificate
		if cert == nil || (certID != "" && certID != fmt.Sprintf("entry-%d", i+1)) || !bytes.Equal(public, cert.RawSubjectPublicKeyInfo) {
			continue
		}
		duplicate := false
		for _, existing := range certs {
			duplicate = duplicate || bytes.Equal(existing.Raw, cert.Raw)
		}
		if !duplicate {
			certs = append(certs, cert)
		}
	}
	if len(certs) != 1 {
		return nil, nil, fmt.Errorf("selection contains %d certificates matching the private key; use inspect and select one with --cert-entry entry-N", len(certs))
	}
	return key, certs[0], nil
}

// Follow only issuers present in the PFX, checking names and signatures rather
// than trusting bag order. No network lookup or trust/date validation is done.
func extractPFXChain(cert *x509.Certificate, info *pkcs12.Inspection) ([]byte, error) {
	seen := map[string]bool{string(cert.Raw): true}
	var chain []byte
	for {
		if bytes.Equal(cert.RawIssuer, cert.RawSubject) && cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil {
			return chain, nil
		}
		var issuer *x509.Certificate
		for _, entry := range info.Entries {
			candidate := entry.Certificate
			if candidate == nil || !bytes.Equal(cert.RawIssuer, candidate.RawSubject) || cert.CheckSignatureFrom(candidate) != nil {
				continue
			}
			if issuer != nil && !bytes.Equal(issuer.Raw, candidate.Raw) {
				return nil, errors.New("multiple possible CA chains in PFX; issuer selection is ambiguous")
			}
			issuer = candidate
		}
		if issuer == nil {
			return chain, nil
		}
		if seen[string(issuer.Raw)] {
			return nil, errors.New("certificate chain in PFX contains a cycle")
		}
		seen[string(issuer.Raw)] = true
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.Raw})...)
		cert = issuer
	}
}
