package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"go.yaml.in/yaml/v3"
)

type configMapOptions struct {
	manifest, key, file, out, name, namespace string
	dryRun, create                            bool
}

type configMapChange struct {
	name, namespace  string
	oldSize, newSize int
	changed          bool
}

var configMapKey = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

func setConfigMapBinary(o configMapOptions, stdout io.Writer) error {
	if o.manifest == "" || o.file == "" || o.key == "" {
		return errors.New("specify nonempty --manifest, --file and --key")
	}
	if !configMapKey.MatchString(o.key) {
		return errors.New("--key may contain only letters, digits, '.', '_' and '-'")
	}
	info, err := os.Lstat(o.manifest)
	if err != nil {
		return fmt.Errorf("stat manifest: %w", err)
	}
	if o.out == "" && !o.dryRun && !info.Mode().IsRegular() {
		return errors.New("in-place update requires a regular manifest file, not a symlink")
	}
	original, err := os.ReadFile(o.manifest)
	if err != nil {
		return fmt.Errorf("read manifest: %w", err)
	}
	payload, err := os.ReadFile(o.file)
	if err != nil {
		return fmt.Errorf("read binary file: %w", err)
	}
	updated, change, err := updateConfigMap(original, payload, o)
	if err != nil {
		return err
	}
	target := change.name
	if change.namespace != "" {
		target = change.namespace + "/" + target
	}
	action := "Target"
	if o.dryRun {
		action = "Dry run"
	} else if !change.changed && o.out == "" {
		action = "Unchanged"
	}
	fmt.Fprintf(stdout, "%s: ConfigMap %s, binaryData[%q], %d -> %d bytes\n", action, target, o.key, change.oldSize, change.newSize)
	if o.dryRun || (!change.changed && o.out == "") {
		return nil
	}
	if o.out != "" {
		if err := writeNewFile(o.out, updated); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Written %s\n", o.out)
		return nil
	}
	// Prepare and sync the replacement before creating the non-overwriting
	// backup. Rename makes the replacement atomic on the same filesystem.
	temp, err := os.CreateTemp(filepath.Dir(o.manifest), ".ssl-toolbox-*.yml")
	if err != nil {
		return fmt.Errorf("prepare manifest replacement: %w", err)
	}
	defer os.Remove(temp.Name())
	defer temp.Close()
	if err := temp.Chmod(info.Mode().Perm()); err != nil {
		return err
	}
	if _, err := temp.Write(updated); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	currentInfo, err := os.Lstat(o.manifest)
	if err != nil || !os.SameFile(info, currentInfo) {
		return errors.New("manifest changed while preparing update; retry")
	}
	current, err := os.ReadFile(o.manifest)
	if err != nil {
		return err
	}
	if !bytes.Equal(current, original) {
		return errors.New("manifest changed while preparing update; retry")
	}
	backup := o.manifest + ".bak"
	if err := writeNewFile(backup, original); err != nil {
		return fmt.Errorf("create backup: %w", err)
	}
	if err := os.Rename(temp.Name(), o.manifest); err != nil {
		return fmt.Errorf("replace manifest (original backup retained): %w", err)
	}
	fmt.Fprintf(stdout, "Written %s; backup %s\n", o.manifest, backup)
	return nil
}

func updateConfigMap(original, payload []byte, o configMapOptions) ([]byte, configMapChange, error) {
	documents, root, change, err := selectConfigMap(original, o)
	if err != nil {
		return nil, change, err
	}
	if mapField(mapField(root, "data"), o.key) != nil {
		return nil, change, errors.New("key already exists in data; cannot also create it in binaryData")
	}
	binary := mapField(root, "binaryData")
	value := mapField(binary, o.key)
	if value == nil && !o.create {
		return nil, change, fmt.Errorf("binaryData key %q does not exist; use --create to add it", o.key)
	}
	if value != nil {
		if value.Kind != yaml.ScalarNode || value.Tag != "!!str" || value.Anchor != "" {
			return nil, change, errors.New("existing binaryData value must be an unanchored string")
		}
		decoded, err := base64.StdEncoding.DecodeString(value.Value)
		if err != nil {
			return nil, change, fmt.Errorf("existing binaryData[%q] is not valid base64", o.key)
		}
		change.oldSize = len(decoded)
		change.changed = !bytes.Equal(decoded, payload)
	} else {
		change.changed = true
	}
	change.newSize = len(payload)
	if !change.changed {
		return original, change, nil
	}
	if binary == nil {
		binary = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		root.Content = append(root.Content, stringNode("binaryData"), binary)
	}
	if value == nil {
		value = stringNode("")
		binary.Content = append(binary.Content, stringNode(o.key), value)
	}
	value.Value = base64.StdEncoding.EncodeToString(payload)
	value.Tag = "!!str"
	value.Style = 0
	var result bytes.Buffer
	encoder := yaml.NewEncoder(&result)
	encoder.SetIndent(2)
	for _, doc := range documents {
		if err := encoder.Encode(doc); err != nil {
			return nil, change, fmt.Errorf("encode YAML: %w", err)
		}
	}
	if err := encoder.Close(); err != nil {
		return nil, change, err
	}
	return result.Bytes(), change, nil
}

func stringNode(value string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value}
}
func mapField(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}
func scalarField(node *yaml.Node, key string) string {
	value := mapField(node, key)
	if value == nil || value.Kind != yaml.ScalarNode {
		return ""
	}
	return value.Value
}
func validateYAML(node *yaml.Node) error {
	if node.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i]
			if key.Kind != yaml.ScalarNode {
				return errors.New("complex YAML mapping keys are unsupported")
			}
			if seen[key.Value] {
				return fmt.Errorf("duplicate YAML key %q", key.Value)
			}
			seen[key.Value] = true
		}
	}
	for _, child := range node.Content {
		if err := validateYAML(child); err != nil {
			return err
		}
	}
	return nil
}

func selectConfigMap(original []byte, o configMapOptions) ([]*yaml.Node, *yaml.Node, configMapChange, error) {
	var change configMapChange
	decoder := yaml.NewDecoder(bytes.NewReader(original))
	var documents []*yaml.Node
	var matches []*yaml.Node
	for {
		var doc yaml.Node
		err := decoder.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, change, fmt.Errorf("parse YAML: %w", err)
		}
		if err := validateYAML(&doc); err != nil {
			return nil, nil, change, err
		}
		documents = append(documents, &doc)
		if len(doc.Content) == 0 {
			continue
		}
		root := doc.Content[0]
		if scalarField(root, "kind") != "ConfigMap" || scalarField(root, "apiVersion") != "v1" {
			continue
		}
		metadata := mapField(root, "metadata")
		name, namespace := scalarField(metadata, "name"), scalarField(metadata, "namespace")
		if (o.name == "" || o.name == name) && (o.namespace == "" || o.namespace == namespace) {
			matches = append(matches, root)
		}
	}
	if len(matches) == 0 {
		return nil, nil, change, errors.New("no matching v1 ConfigMap found")
	}
	if len(matches) != 1 {
		return nil, nil, change, errors.New("multiple ConfigMaps match; specify --name and, if needed, --namespace")
	}
	root := matches[0]
	metadata := mapField(root, "metadata")
	change.name, change.namespace = scalarField(metadata, "name"), scalarField(metadata, "namespace")
	if change.name == "" {
		return nil, nil, change, errors.New("ConfigMap metadata.name is missing")
	}
	// YAML aliases/merge keys in the target mappings are refused rather than
	// modifying an anchor shared by other resources.
	for _, node := range []*yaml.Node{root, metadata, mapField(root, "binaryData"), mapField(root, "data")} {
		if node != nil && (node.Kind != yaml.MappingNode || node.Anchor != "" || mapField(node, "<<") != nil) {
			return nil, nil, change, errors.New("target ConfigMap mappings must be explicit mappings without YAML aliases or merges")
		}
	}
	return documents, root, change, nil
}
