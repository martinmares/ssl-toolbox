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
	"strings"

	"github.com/spf13/cobra"
	"software.sslmate.com/src/go-pkcs12"
)

func newPFXCommand(stdout, stderr io.Writer) *cobra.Command {
	parent := &cobra.Command{Use: "pfx", Short: "Create PFX identities and change PFX/key passwords", Args: cobra.NoArgs}
	parent.RunE = func(cmd *cobra.Command, args []string) error { return cmd.Help() }
	var keyPath, certPath, out, passEnv, passFile, keyPassEnv, keyPassFile string
	var chainFiles []string
	cmd := &cobra.Command{Use: "create", Short: "Package a matching private key, certificate and optional CA chain into modern PFX", Args: cobra.NoArgs,
		Example: "  ssl-toolbox pfx create --key certificates/server.key --cert issued.pem --chain ca-chain.pem --out server.pfx\n  ssl-toolbox pfx create --key certificates/server.key --cert issued.cer --out server.pfx --out-pass-env PFX_PASSWORD",
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			if strings.TrimSpace(out) == "" {
				return errors.New("--out must not be empty")
			}
			if _, err := os.Lstat(out); err == nil {
				return fmt.Errorf("output %q already exists", out)
			} else if !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("check output: %w", err)
			}
			cert, err := readIdentityCertificate(certPath)
			if err != nil {
				return err
			}
			key, err := readPrivateKeyFile(keyPath, &inspectPassword{env: keyPassEnv, file: keyPassFile, stderr: stderr})
			if err != nil {
				return fmt.Errorf("read private key: %w", err)
			}
			signer, ok := key.(crypto.Signer)
			if !ok {
				return errors.New("unsupported private key type")
			}
			public, err := x509.MarshalPKIXPublicKey(signer.Public())
			if err != nil {
				return err
			}
			if !bytes.Equal(public, cert.RawSubjectPublicKeyInfo) {
				return errors.New("private key does not match the issued certificate")
			}
			candidates, err := readCAs(chainFiles)
			if err != nil {
				return err
			}
			chain, err := buildCertificateChain(cert, candidates)
			if err != nil {
				return err
			}
			if len(chain) != len(candidates) {
				return errors.New("--chain contains certificates outside the issued certificate's CA chain")
			}
			pw, err := readNewPassword(passEnv, passFile, stderr)
			if err != nil {
				return err
			}
			data, err := pkcs12.Modern2023.Encode(key, cert, chain, pw)
			if err != nil {
				return fmt.Errorf("encode PFX: %w", err)
			}
			if err := writeNewFile(out, data); err != nil {
				return err
			}
			_, err = fmt.Fprintf(stdout, "Created %s (PKCS#12; matching private key and certificate; %d CA chain certificates)\n", out, len(chain))
			return err
		},
	}
	f := cmd.Flags()
	f.StringVar(&keyPath, "key", "", "Private key in PEM or DER, normally the key saved with the CSR")
	f.StringVar(&certPath, "cert", "", "One issued X.509 certificate in PEM or DER (.cer/.crt extensions do not select the format)")
	f.StringArrayVar(&chainFiles, "chain", nil, "CA chain PEM file or bundle; repeatable, input order does not matter")
	f.StringVar(&out, "out", "", "New PFX file; parent directory must exist")
	f.StringVar(&passEnv, "out-pass-env", "", "Environment variable containing the new PFX/key password")
	f.StringVar(&passFile, "out-pass-file", "", "File containing the new PFX/key password")
	f.StringVar(&keyPassEnv, "key-pass-env", "", "Environment variable containing the existing encrypted key password")
	f.StringVar(&keyPassFile, "key-pass-file", "", "File containing the existing encrypted key password")
	cmd.MarkFlagsMutuallyExclusive("out-pass-env", "out-pass-file")
	cmd.MarkFlagsMutuallyExclusive("key-pass-env", "key-pass-file")
	for _, flag := range []string{"key", "cert", "out"} {
		_ = cmd.MarkFlagRequired(flag)
	}
	parent.AddCommand(cmd, newPFXChangePasswordCommand(stdout, stderr))
	return parent
}

func readIdentityCertificate(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read issued certificate: %w", err)
	}
	if bytes.HasPrefix(bytes.TrimSpace(data), []byte("-----BEGIN ")) {
		block, rest := pem.Decode(bytes.TrimSpace(data))
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
			return nil, errors.New("--cert must contain exactly one CERTIFICATE PEM block; use --chain for CA certificates")
		}
		data = block.Bytes
	}
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("parse issued certificate: %w", err)
	}
	return cert, nil
}
