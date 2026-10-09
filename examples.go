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
	{Command: "version", Description: "Read the version embedded from VERSION and inspect release build metadata.", Examples: []commandExample{
		{Title: "Print the release version", Description: "Works for a plain go build as well as Justfile builds. VERSION is read at build time, not from your current working directory.", Shell: "ssl-toolbox --version"},
		{Title: "Inspect build metadata", Description: "Justfile injects the Git commit and UTC build date. Plain builds report unknown metadata unless linker flags were supplied.", Shell: "ssl-toolbox version"},
	}},
	{Command: "inspect", Description: "Identify PFX, JKS, PEM or DER by content and inspect all supported certificates and keys. Passwords are requested only when needed; private material is never printed.", Examples: []commandExample{
		{Title: "Inspect a keystore and its protection", Description: "A .jks file may actually be PKCS#12. Shows every identity and certificate, aliases, validity dates, CA status, SAN, usages, fingerprints and encryption/MAC parameters. Keys are matched to certificates by their public-key fingerprint.", Shell: "ssl-toolbox inspect client.jks"},
		{Title: "Inspect a PEM bundle or DER certificate", Description: "Plain certificates and keys need no password. All PEM blocks are read; encrypted PEM/PKCS#8 keys request a password. Date status does not verify trust or revocation.", Shell: "ssl-toolbox inspect ca-bundle.pem\nssl-toolbox inspect client.der"},
		{Title: "Export metadata as JSON", Description: "Contains metadata only, never passwords or private key bytes. Password prompts go to stderr, leaving stdout as JSON. Environment flags name variables supplied by your shell or secret provider.", Shell: "ssl-toolbox inspect client.pfx --pass-env STORE_PASSWORD --json > inspection.json"},
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
				fmt.Fprintf(&output, "\n    %s\n", paint("FILE · "+file.Name+" (YAML)", "1;34"))
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
