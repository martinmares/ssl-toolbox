package main

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
)

type exampleFile struct{ Name, Content string }
type commandExample struct {
	Title, Description, Shell string
	Files                     []exampleFile
}
type commandExamples struct {
	Command, Description string
	Examples             []commandExample
}

var examplesCatalog = []commandExamples{
	{Command: "csr create", Description: "Create a SHA-256 certificate signing request with a new RSA key or reuse an existing RSA key. Send the CSR to your CA; keep the private key locally.", Examples: []commandExample{
		{Title: "Generate a key and CSR", Description: "Creates certificates/server.key (unencrypted PKCS#8, RSA 4096 by default) and certificates/server.csr. --out-dir is a directory; --name is the basename and defaults to CN. Missing directories are created; existing files are never overwritten. Subject fields other than CN are optional. CN is not automatically added to SAN.", Shell: "ssl-toolbox csr create \\\n  --cn server.example.org --email admin@example.org \\\n  --country CZ --province \"Czech Republic\" --locality Prague \\\n  --organization Example --organizational-unit WEB \\\n  --dns server.example.org --dns server --ip 192.0.2.10 \\\n  --out-dir certificates --name server"},
		{Title: "Read DNS aliases from a file", Description: "One DNS name per line; empty lines and # comments are ignored. Combine with repeated --dns and --ip flags. Duplicate SANs are removed; IP addresses must use --ip. Wildcard DNS names are supported; choose an explicit filename for a wildcard CN. --bits selects a new RSA key size: 2048, 3072, 4096 or 8192.", Shell: "ssl-toolbox csr create --cn server.example.org \\\n  --sans-file dns-names.txt --ip 2001:db8::10 \\\n  --out-dir certificates --name server", Files: []exampleFile{{Name: "dns-names.txt", Content: "# Requested DNS names\nserver.example.org\nserver\n"}}},
		{Title: "Reuse an existing RSA key in CI", Description: "Only creates requests/server.csr. The original key is neither modified nor copied. Supports PEM/DER PKCS#1 and PKCS#8, including encrypted keys. Password ENV flags take variable names; FILE flags take paths. Choose one source. --key and --bits cannot be combined.", Shell: "ssl-toolbox csr create --cn server.example.org --dns server.example.org \\\n  --key existing.key --key-pass-env KEY_PASSWORD \\\n  --out-dir requests --name server\nssl-toolbox csr create --cn server.example.org --dns server.example.org \\\n  --key existing.key --key-pass-file \"$KEY_PASSWORD_FILE\" \\\n  --out-dir another-request --name server"},
		{Title: "Inspect the request before sending it", Description: "Shows the requested subject, public key, DNS/IP SANs and whether the CSR signature verifies. A CSR has no validity dates and is not an issued certificate. PDF reports contain metadata only.", Shell: "ssl-toolbox inspect certificates/server.csr\nssl-toolbox inspect certificates/server.csr --json\nssl-toolbox inspect certificates/server.csr --pdf request-report.pdf"},
	}},
	{Command: "csr batch", Description: "Generate one key and CSR per YAML request, using shared Subject defaults and explicit SANs per request. The entire batch is validated before any key generation or writes.", Examples: []commandExample{
		{Title: "Preview and generate a batch", Description: "--out-dir is relative to your working directory. Required request names become filename basenames and must be unique ignoring case. Subject fields inherit defaults; an explicit empty string clears a field. SANs are per request and CN is not added automatically. --dry-run validates existing keys, shows the complete plan and writes nothing. A complete example is in examples/csr-batch.yaml.", Shell: "ssl-toolbox csr batch --config requests.yaml --out-dir certificates --dry-run\nssl-toolbox csr batch --config requests.yaml --out-dir certificates", Files: []exampleFile{{Name: "requests.yaml", Content: "defaults:\n  rsaBits: 4096\n  subject:\n    country: CZ\n    organization: Example\nrequests:\n  - name: frontend\n    subject:\n      commonName: frontend.example.org\n    san:\n      dns: [frontend.example.org, frontend]\n      ip: [192.0.2.10]\n  - name: backend\n    subject:\n      commonName: backend.example.org\n    san:\n      dns: [backend.example.org, backend]\n      ip: [\"2001:db8::20\"]\n"}}},
		{Title: "Reuse an encrypted key from YAML", Description: "key.file and key.passwordFile paths resolve relative to the YAML file. key.passwordEnv names a secret environment variable, not the secret value. Choose one password source; plaintext passwords in YAML are unsupported. Only a CSR is created when a key is reused. Request rsaBits cannot be combined with key.", Shell: "ssl-toolbox csr batch --config reuse.yaml --out-dir requests --dry-run\nssl-toolbox csr batch --config reuse.yaml --out-dir requests", Files: []exampleFile{{Name: "reuse.yaml", Content: "requests:\n  - name: renewal\n    subject:\n      commonName: server.example.org\n    san:\n      dns: [server.example.org, server]\n    key:\n      file: keys/server.key\n      passwordEnv: KEY_PASSWORD\n      # Alternatively: passwordFile: secrets/key-password\n"}}},
		{Title: "Review results and reruns", Description: "Existing output files are errors, including in dry-run; they are never silently skipped. Generation is sequential. A runtime error stops the batch and lists completed requests; their files remain. Use a new directory or a config containing only unfinished requests after reviewing a partial run. Unknown YAML fields, duplicate keys, aliases, merges and multiple documents are rejected. Batch PFX packaging is not part of this command.", Shell: "ssl-toolbox inspect certificates/frontend.csr --pdf frontend-request.pdf\nssl-toolbox inspect certificates/backend.csr --json"},
	}},
	{Command: "pfx change-password", Description: "Change the PFX password and the private key password together, replacing the same file in place. A verified temporary PFX is written in the same directory before replacement.", Examples: []commandExample{
		{Title: "Change passwords interactively", Description: "Prompts for the current password, a nonempty new password and confirmation. The same new password protects the PFX and every private key. Re-encrypts using modern AES-256/SHA-256 protection, retaining certificate/key contents, aliases, local key IDs, issuer chains and trusted CA entries. Multiple private identities and certificate-only stores are supported. The input must be a regular file; symlinks are rejected.", Shell: "ssl-toolbox pfx change-password client.pfx"},
		{Title: "Change passwords in a pipeline", Description: "ENV flags name secret variables; FILE flags take file paths and accept GitLab File variables. No password values are printed. Existing file permissions are retained. A failure before replacement leaves the original untouched, and temporary files are cleaned up. Concurrent changes detected before replacement stop the update. Replacement uses a same-directory rename, atomic on Unix; no backup is created.", Shell: "ssl-toolbox pfx change-password client.pfx \\\n  --in-pass-env OLD_PFX_PASSWORD --out-pass-env NEW_PFX_PASSWORD\nssl-toolbox pfx change-password client.pfx \\\n  --in-pass-file \"$OLD_PASSWORD_FILE\" --out-pass-file \"$NEW_PASSWORD_FILE\""},
		{Title: "Keep the original file instead", Description: "When a separate output is desired, use convert rather than an in-place password change. Existing output files are never overwritten.", Shell: "ssl-toolbox convert --in original.pfx --out new-password.pfx \\\n  --in-pass-env OLD_PFX_PASSWORD --out-pass-env NEW_PFX_PASSWORD"},
	}},
	{Command: "pfx create", Description: "After the CA returns the issued certificate, combine it with the original private key and optional CA chain into modern PKCS#12. The same new password protects the PFX and private key.", Examples: []commandExample{
		{Title: "Package the CA response", Description: "--cert is one issued certificate in PEM or DER; a .cer extension does not select the format. --chain accepts repeatable CA PEM files or bundles and orders issuers by names and signatures. A certificate/key mismatch, unrelated CA certificates or existing output are errors. Chain trust, validity and revocation are not verified by packaging.", Shell: "ssl-toolbox pfx create \\\n  --key certificates/server.key --cert issued.pem \\\n  --chain intermediate.pem --chain root.pem \\\n  --out certificates/server.pfx\nssl-toolbox inspect certificates/server.pfx"},
		{Title: "Package without prompts in a pipeline", Description: "Use --out-pass-env or --out-pass-file for a nonempty new PFX/key password. Existing encrypted keys use --key-pass-env or --key-pass-file. No secret values or private key bytes are printed. Parent directory for --out must exist.", Shell: "ssl-toolbox pfx create --key certificates/server.key --cert issued.cer \\\n  --chain ca-chain.pem --out certificates/server.pfx --out-pass-env PFX_PASSWORD\nssl-toolbox pfx create --key encrypted.key --key-pass-file \"$KEY_PASSWORD_FILE\" \\\n  --cert issued.pem --out encrypted-identity.pfx --out-pass-file \"$PFX_PASSWORD_FILE\""},
		{Title: "Convert the resulting identity to JKS", Description: "Use the existing convert command after creating PFX if the application requires a real JKS store. Supply passwords through your shell or secret provider.", Shell: "ssl-toolbox convert --in certificates/server.pfx --out certificates/server.jks \\\n  --format jks --alias server --in-pass-env PFX_PASSWORD --out-pass-env JKS_PASSWORD"},
	}},
	{Command: "extract", Description: "Export one PFX identity as clean PEM files: an unencrypted PKCS#8 private key, its certificate and any available CA chain. Existing files are never overwritten.", Examples: []commandExample{
		{Title: "Extract certificate and key together", Description: "Creates export/client.key and export/client.pem, plus client.chain.pem if issuers are present in the PFX. Files have permissions 0600. Tries an empty PFX password first, then prompts if necessary.", Shell: "ssl-toolbox extract client.pfx --out-dir ./export"},
		{Title: "Extract with an environment password", Description: "Set STORE_PASSWORD through your shell or secret provider first. --pass-env takes the variable name. The exported key remains unencrypted; private key bytes and passwords are never printed.", Shell: "ssl-toolbox extract client.pfx --out-dir ./export --pass-env STORE_PASSWORD"},
		{Title: "Extract with a File password", Description: "GitLab File variables contain paths. Quote and expand the path for --pass-file. Choose one password source: --pass-env or --pass-file.", Shell: "ssl-toolbox extract client.pfx --out-dir ./export --pass-file \"$STORE_PASSWORD_FILE\""},
		{Title: "Select one of multiple identities", Description: "Replace entry-3 with the private key entry ID shown by inspect for the same unchanged PFX. Multiple keys require explicit selection.", Shell: "ssl-toolbox inspect identities.pfx\nssl-toolbox extract identities.pfx --out-dir ./export --entry entry-3"},
		{Title: "Select a matching certificate explicitly", Description: "If multiple different certificates match the selected key, also use --cert-entry. Replace entry-3 and entry-2 with the private key and matching certificate IDs from inspect. Each extraction example is an alternative; existing output files are never overwritten.", Shell: "ssl-toolbox extract identities.pfx --out-dir ./export --entry entry-3 --cert-entry entry-2"},
	}},
	{Command: "version", Description: "Read the version embedded from VERSION and inspect release build metadata.", Examples: []commandExample{
		{Title: "Print the release version", Description: "Works for a plain go build as well as Justfile builds. VERSION is read at build time, not from your current working directory.", Shell: "ssl-toolbox --version"},
		{Title: "Inspect build metadata", Description: "Justfile injects the Git commit and UTC build date. Plain builds report unknown metadata unless linker flags were supplied.", Shell: "ssl-toolbox version"},
	}},
	{Command: "inspect", Description: "Identify PFX, JKS, PEM or DER by content and inspect all supported certificates and keys. Passwords are requested only when needed; private material is never printed.", Examples: []commandExample{
		{Title: "Inspect a keystore and its protection", Description: "A .jks file may actually be PKCS#12. Shows every identity and certificate, aliases, validity dates, CA status, SAN, usages, fingerprints and encryption/MAC parameters. Keys are matched to certificates by their public-key fingerprint.", Shell: "ssl-toolbox inspect client.jks"},
		{Title: "Inspect a PEM bundle or DER certificate", Description: "Plain certificates and keys need no password. All PEM blocks are read, including OpenSSL exports with Bag Attributes, Key Attributes, subject= and issuer= metadata before or between blocks. Other text outside PEM blocks is rejected. Encrypted PEM/PKCS#8 keys request a password. Date status does not verify trust or revocation.", Shell: "ssl-toolbox inspect ca-bundle.pem\nssl-toolbox inspect client.der"},
		{Title: "Export metadata as JSON", Description: "Contains metadata only, never passwords or private key bytes. Password prompts go to stderr, leaving stdout as JSON. Environment flags name variables supplied by your shell or secret provider.", Shell: "ssl-toolbox inspect client.pfx --pass-env STORE_PASSWORD --json > inspection.json"},
		{Title: "Export a PDF report for sharing", Description: "Creates a colored, paginated PDF with embedded fonts, all entries and the UTC generation time. Expiry estimates describe the time of inspection. Passwords and private key bytes are never included. Existing files are not overwritten; --pdf and --json are mutually exclusive. Works without a browser or external PDF tools, including in CI.", Shell: "ssl-toolbox inspect client.pfx --pdf inspection.pdf\nssl-toolbox inspect client.jks --pass-file \"$STORE_PASSWORD_FILE\" --expiry-warning-days 60 --pdf keystore-report.pdf"},
		{Title: "Use a separate JKS key password", Description: "First tries the store password for each key. If that fails, --key-pass-env supplies the separate key password; without it, the tool prompts for that alias.", Shell: "ssl-toolbox inspect client.jks --pass-env STORE_PASSWORD --key-pass-env KEY_PASSWORD"},
		{Title: "Colors and expiration warnings", Description: "Auto colors respect NO_COLOR, TERM=dumb and output redirection. Expired certificates are red; certificates expiring within the warning window are yellow. Explicit labels remain visible without colors. JSON never contains ANSI codes.", Shell: "ssl-toolbox inspect client.pfx --expiry-warning-days 60 --color always"},
		{Title: "Inspect using GitLab File passwords", Description: "GitLab File variables contain paths. Quote and expand them for FILE flags. Supply a separate JKS key file only when required. Files lose one trailing LF/CRLF; spaces are preserved.", Shell: "ssl-toolbox inspect client.jks --pass-file \"$STORE_PASSWORD_FILE\" --key-pass-file \"$KEY_PASSWORD_FILE\" --json"},
	}},
	{Command: "convert", Description: "Read one PKCS#12 identity (or truststore) and write modern PFX or real JKS. Existing output files are never overwritten.", Examples: []commandExample{
		{Title: "Replace legacy encryption and change the password", Description: "Supports RC2/3DES and Windows BER. The new PFX uses AES-256/SHA-256; the same new password protects both the store and private key. Passwords are prompted without echo.", Shell: "ssl-toolbox convert --in legacy-client.pfx --out modern-client.pfx"},
		{Title: "Export a real JKS", Description: "The format is explicit: a .jks filename alone does not select JKS. The key alias defaults to client and is stored in lowercase. The client's certificate chain is preserved.", Shell: "ssl-toolbox convert --in client.pfx --out client.jks \\\n  --format jks --alias client"},
		{Title: "Add independent trusted CA entries", Description: "Repeat --add-ca to import multiple PEM files. Bundles are supported and identical certificates are deduplicated. Imported CA:TRUE certificates become trustedCertEntry, separate from the client's own chain. Works with both output formats.", Shell: "ssl-toolbox convert --in client.pfx --out client-with-ca.jks \\\n  --format jks --alias client \\\n  --add-ca root-ca.pem --add-ca another-ca.pem"},
		{Title: "Use passwords supplied by your environment", Description: "Set these variables through your shell or secret provider first. Flags contain variable names, not passwords. A missing variable is an error; the new password must not be empty.", Shell: "ssl-toolbox convert --in client.pfx --out modern.pfx \\\n  --in-pass-env OLD_PFX_PASSWORD --out-pass-env NEW_PFX_PASSWORD"},
		{Title: "Convert an existing PKCS#12 truststore", Description: "The input may contain only trusted certificates, or both an identity and trust entries. Trust roles are preserved and CA aliases are normalized to SHA-256 fingerprints. JKS input is not supported.", Shell: "ssl-toolbox convert --in truststore.pfx --out truststore.jks --format jks"},
		{Title: "Convert in a GitLab pipeline with File variables", Description: "Both existing and new passwords come from files. There is no prompt or confirmation, and password contents are never logged. ENV and FILE cannot be combined for the same password; different password sources may be mixed.", Shell: "ssl-toolbox convert --in client.pfx --out modern.pfx --in-pass-file \"$OLD_PFX_PASSWORD_FILE\" --out-pass-file \"$NEW_PFX_PASSWORD_FILE\""},
	}},
	{Command: "truststore", Description: "Create a certificate-only truststore from PEM files. It has no private key and asks only for a new store password.", Examples: []commandExample{
		{Title: "Create a Java-compatible PKCS#12 truststore", Description: "Each trusted certificate gets a ca-<SHA-256 fingerprint> alias and Java trust attributes. Configure your application to use this file as its truststore.", Shell: "ssl-toolbox truststore --out truststore.pfx \\\n  --add-ca root-ca.pem --add-ca ca-bundle.pem"},
		{Title: "Create a JKS truststore", Description: "The PEM parser rejects empty files, malformed blocks and non-CA certificates. JKS uses its own legacy protection; AES-256/SHA-256 applies to PFX output.", Shell: "ssl-toolbox truststore --out truststore.jks --format jks \\\n  --add-ca ca-bundle.pem --out-pass-env NEW_PFX_PASSWORD"},
		{Title: "Create a truststore without interactive prompts", Description: "Pass the path from a GitLab File variable or a mounted secret. The same new password protects the resulting store; an empty new password is rejected.", Shell: "ssl-toolbox truststore --out truststore.pfx --add-ca ca-bundle.pem --out-pass-file \"$NEW_PFX_PASSWORD_FILE\""},
	}},
	{Command: "configmap set-binary", Description: "Replace a ConfigMap binaryData value with the base64-encoded raw bytes of a file. This edits YAML on disk; it does not contact Kubernetes.", Examples: []commandExample{
		{Title: "Preview a replacement", Description: "Shows the selected ConfigMap, key and decoded byte counts. No manifest, output file or backup is written, and the binary/base64 content is not printed.", Files: []exampleFile{{Name: "assets.yml", Content: "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: client-assets\n  namespace: prod\nbinaryData:\n  client.jks: b2xk # old file bytes"}}, Shell: "ssl-toolbox configmap set-binary --manifest assets.yml \\\n  --key client.jks --file new-client.jks --dry-run"},
		{Title: "Replace the existing key in place", Description: "Creates assets.yml.bak with the exact original bytes, then atomically replaces the manifest. An existing backup is never overwritten. The key must exist. An identical value causes no write and no backup.", Shell: "ssl-toolbox configmap set-binary --manifest assets.yml \\\n  --key client.jks --file new-client.jks"},
		{Title: "Write a separate manifest", Description: "--out keeps the source unchanged, creates no .bak and refuses an existing output file. Other documents, values and comments are preserved; YAML formatting may be normalized.", Shell: "ssl-toolbox configmap set-binary --manifest assets.yml \\\n  --key client.jks --file new-client.jks --out updated-assets.yml"},
		{Title: "Select a ConfigMap and create a new binary key", Description: "When several ConfigMaps match, choose metadata.name and optionally metadata.namespace. --create allows adding a missing key or binaryData mapping. A key already in data is rejected to avoid a conflicting manifest.", Shell: "ssl-toolbox configmap set-binary --manifest resources.yml \\\n  --name client-assets --namespace prod \\\n  --key root-ca.der --file root-ca.der --create"},
		{Title: "Preview a keystore manifest in a project directory", Description: "First run with --dry-run. Remove that flag to create a .bak and update the manifest on disk. Review the resulting change before applying it to Kubernetes.", Shell: "ssl-toolbox configmap set-binary \\\n  --manifest manifests/configmap.yaml \\\n  --key client.jks \\\n  --file certificates/client.jks \\\n  --dry-run"},
	}},
	{Command: "configmap extract-binary", Description: "Decode an existing ConfigMap binaryData key into a new binary file. The source manifest stays unchanged; no Kubernetes connection is needed.", Examples: []commandExample{
		{Title: "Recover a keystore from YAML", Description: "The manifest and key are positional arguments. --out is required and must not exist; the binary output has permissions 0600. Prints the byte count and SHA-256, never the binary/base64 contents.", Shell: "ssl-toolbox configmap extract-binary assets.yml client.jks --out extracted.jks"},
		{Title: "Select a ConfigMap in a multi-document manifest", Description: "Use --name and optionally --namespace when the manifest contains several ConfigMaps. The key must be in binaryData; invalid base64, duplicate YAML keys and conflicting data entries are rejected.", Shell: "ssl-toolbox configmap extract-binary resources.yml client.jks --name client-assets --namespace prod --out client.jks"},
		{Title: "Inspect the extracted file", Description: "Run inspect after extraction to identify the actual keystore format and inspect its entries. A protected store requests a password.", Shell: "ssl-toolbox configmap extract-binary assets.yml client.jks --out extracted.jks\nssl-toolbox inspect extracted.jks"},
	}},
}

func newExamplesCommand() *cobra.Command {
	colorMode := "auto"
	cmd := &cobra.Command{Use: "examples", Aliases: []string{"example"}, Short: "Show explained command variants and YAML examples", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			color, err := colorEnabled(cmd.OutOrStdout(), colorMode)
			if err != nil {
				return err
			}
			return writeExamples(cmd.OutOrStdout(), color)
		},
	}
	cmd.Flags().StringVar(&colorMode, "color", "auto", "ANSI colors: auto, always or never (auto respects NO_COLOR and TERM=dumb)")
	return cmd
}

func writeExamples(w io.Writer, color bool) error {
	var output bytes.Buffer
	paint := func(text, code string) string { return paintANSI(text, code, color) }
	fmt.Fprintln(&output, paint("SSL-TOOLBOX COMMAND EXAMPLES", "1;36"))
	fmt.Fprintln(&output, paint("Commands are green (SHELL); input files are blue (FILE).", "2"))
	for _, command := range examplesCatalog {
		fmt.Fprintf(&output, "\n%s\n   %s\n", paint("## "+strings.ToUpper(command.Command), "1;36"), paint(command.Description, "2"))
		for _, example := range command.Examples {
			fmt.Fprintf(&output, "\n  %s\n    %s\n", paint("› "+example.Title, "1;33"), paint(example.Description, "2"))
			for _, file := range example.Files {
				format := "TEXT"
				if strings.HasSuffix(file.Name, ".yml") || strings.HasSuffix(file.Name, ".yaml") {
					format = "YAML"
				}
				fmt.Fprintf(&output, "\n    %s\n", paint("FILE · "+file.Name+" ("+format+")", "1;34"))
				for _, line := range strings.Split(file.Content, "\n") {
					fmt.Fprintln(&output, paint("        "+line, "34"))
				}
			}
			fmt.Fprintln(&output, "\n    "+paint("SHELL", "1;32"))
			for _, line := range strings.Split(example.Shell, "\n") {
				fmt.Fprintln(&output, paint("      "+line, "32"))
			}
		}
	}
	fmt.Fprintln(&output, "\n"+paint("Run 'ssl-toolbox <command> --help' for all flags. Full reference: README.md / README.cs.md", "2"))
	_, err := io.Copy(w, &output)
	return err
}
