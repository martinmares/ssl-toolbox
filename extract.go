package main

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v3"
)

func newExtractBinaryCommand(stdout io.Writer) *cobra.Command {
	var options configMapOptions
	cmd := &cobra.Command{Use: "extract-binary <manifest.yaml> <key>", Short: "Decode a ConfigMap binaryData entry into a new binary file", Args: cobra.ExactArgs(2),
		Example: "  ssl-toolbox configmap extract-binary assets.yml client.jks --out extracted.jks\n  ssl-toolbox configmap extract-binary resources.yml client.jks --name kafka --namespace prod --out client.jks",
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			options.manifest, options.key = args[0], args[1]
			return extractConfigMapBinary(options, stdout)
		},
	}
	cmd.Flags().StringVar(&options.out, "out", "", "New binary output file; must not exist")
	cmd.Flags().StringVar(&options.name, "name", "", "Select metadata.name")
	cmd.Flags().StringVar(&options.namespace, "namespace", "", "Select metadata.namespace")
	_ = cmd.MarkFlagRequired("out")
	return cmd
}

func extractConfigMapBinary(o configMapOptions, stdout io.Writer) error {
	if o.out == "" {
		return errors.New("specify a nonempty --out")
	}
	if !configMapKey.MatchString(o.key) {
		return errors.New("invalid binaryData key")
	}
	original, err := os.ReadFile(o.manifest)
	if err != nil {
		return fmt.Errorf("read manifest: %w", err)
	}
	_, root, change, err := selectConfigMap(original, o)
	if err != nil {
		return err
	}
	if mapField(mapField(root, "data"), o.key) != nil {
		return errors.New("key also exists in data; ambiguous ConfigMap")
	}
	value := mapField(mapField(root, "binaryData"), o.key)
	if value == nil {
		return fmt.Errorf("binaryData key %q does not exist", o.key)
	}
	if value.Kind != yaml.ScalarNode || value.Tag != "!!str" || value.Anchor != "" {
		return errors.New("binaryData value must be an unanchored string")
	}
	payload, err := base64.StdEncoding.DecodeString(value.Value)
	if err != nil {
		return fmt.Errorf("binaryData[%q] is not valid base64", o.key)
	}
	if err := writeNewFile(o.out, payload); err != nil {
		return err
	}
	target := change.name
	if change.namespace != "" {
		target = change.namespace + "/" + target
	}
	_, err = fmt.Fprintf(stdout, "Extracted ConfigMap %s, binaryData[%q] -> %s (%d bytes)\nSHA-256: %x\n", target, o.key, o.out, len(payload), sha256.Sum256(payload))
	return err
}
