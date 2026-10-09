package main

import (
	"github.com/spf13/cobra"
	"io"
)

func newRootCommand(stdout, stderr io.Writer) *cobra.Command {
	root := &cobra.Command{
		Use: "ssl-toolbox", Short: "Keystore inspection, conversion, truststores and ConfigMap binary assets",
		Args: cobra.NoArgs, SilenceErrors: true, Version: currentVersion(),
		RunE: func(cmd *cobra.Command, args []string) error { return cmd.Help() },
	}
	root.SetVersionTemplate("ssl-toolbox version {{.Version}}\n")
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.AddCommand(newStoreCommand(false, stdout, stderr), newStoreCommand(true, stdout, stderr), newConfigMapCommand(stdout), newExamplesCommand(), newVersionCommand(), newInspectCommand(stdout, stderr))
	return root
}

func newStoreCommand(trustOnly bool, stdout, stderr io.Writer) *cobra.Command {
	var options conversionOptions
	cmd := &cobra.Command{Use: "convert", Short: "Convert PFX to modern PFX or JKS, optionally adding trusted CA certificates",
		Example: "  ssl-toolbox convert --in old.pfx --out new.pfx\n  ssl-toolbox convert --in old.pfx --out client.jks --format jks --alias kafka --add-ca root.pem",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			return convertFile(options, stdout, stderr)
		},
	}
	if trustOnly {
		cmd.Use = "truststore"
		cmd.Short = "Create a certificate-only truststore from CA PEM files"
		cmd.Example = "  ssl-toolbox truststore --out truststore.pfx --add-ca root.pem --add-ca bundle.pem\n  ssl-toolbox truststore --out truststore.jks --format jks --add-ca root.pem"
	}
	flags := cmd.Flags()
	flags.StringVar(&options.out, "out", "", "New output file (must not exist)")
	flags.StringVar(&options.format, "format", "pfx", "Output format: pfx or jks; filename extension does not select it")
	flags.StringVar(&options.outEnv, "out-pass-env", "", "Environment variable with new password; otherwise prompt twice")
	flags.StringVar(&options.outPassFile, "out-pass-file", "", "File containing new password (supports GitLab File variables)")
	cmd.MarkFlagsMutuallyExclusive("out-pass-env", "out-pass-file")
	flags.StringArrayVar(&options.caFiles, "add-ca", nil, "Trusted CA PEM file; repeatable, bundles supported")
	if trustOnly {
		_ = cmd.MarkFlagRequired("add-ca")
	} else {
		flags.StringVar(&options.in, "in", "", "Input PKCS#12 file (legacy and BER supported)")
		flags.StringVar(&options.inEnv, "in-pass-env", "", "Environment variable with input password; otherwise prompt")
		flags.StringVar(&options.inPassFile, "in-pass-file", "", "File containing input password")
		cmd.MarkFlagsMutuallyExclusive("in-pass-env", "in-pass-file")
		flags.StringVar(&options.alias, "alias", "client", "Private key alias for JKS output")
		_ = cmd.MarkFlagRequired("in")
	}
	if trustOnly {
		options.alias = "client"
	}
	_ = cmd.MarkFlagRequired("out")
	return cmd
}

func newConfigMapCommand(stdout io.Writer) *cobra.Command {
	parent := &cobra.Command{Use: "configmap", Short: "Read and edit ConfigMap binary assets in YAML manifests", Args: cobra.NoArgs}
	parent.RunE = func(cmd *cobra.Command, args []string) error { return cmd.Help() }
	var options configMapOptions
	cmd := &cobra.Command{Use: "set-binary", Short: "Replace a binaryData entry with the base64-encoded contents of a file",
		Example: "  ssl-toolbox configmap set-binary --manifest assets.yml --key client.jks --file new.jks --dry-run\n  ssl-toolbox configmap set-binary --manifest assets.yml --key client.jks --file new.jks\n  ssl-toolbox configmap set-binary --manifest assets.yml --name kafka --key client.jks --file new.jks --out updated.yml",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			return setConfigMapBinary(options, stdout)
		},
	}
	f := cmd.Flags()
	f.StringVar(&options.manifest, "manifest", "", "YAML manifest to read; updated in place unless --out is set")
	f.StringVar(&options.key, "key", "", "Key in binaryData (must exist unless --create is set)")
	f.StringVar(&options.file, "file", "", "Binary file whose bytes will replace the value")
	f.StringVar(&options.out, "out", "", "Write a new manifest instead of modifying the original; must not exist")
	f.StringVar(&options.name, "name", "", "Select metadata.name when the manifest contains multiple ConfigMaps")
	f.StringVar(&options.namespace, "namespace", "", "Select metadata.namespace")
	f.BoolVar(&options.dryRun, "dry-run", false, "Show target and decoded byte counts without writing or printing base64")
	f.BoolVar(&options.create, "create", false, "Allow creating a missing binaryData key")
	for _, name := range []string{"manifest", "key", "file"} {
		_ = cmd.MarkFlagRequired(name)
	}
	parent.AddCommand(cmd, newExtractBinaryCommand(stdout))
	return parent
}
