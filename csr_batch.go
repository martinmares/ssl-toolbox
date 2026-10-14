package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v3"
)

type csrBatchSubject struct {
	CommonName         *string `yaml:"commonName"`
	Country            *string `yaml:"country"`
	Province           *string `yaml:"province"`
	Locality           *string `yaml:"locality"`
	Organization       *string `yaml:"organization"`
	OrganizationalUnit *string `yaml:"organizationalUnit"`
	Email              *string `yaml:"email"`
}

type csrBatchConfig struct {
	Defaults struct {
		Subject csrBatchSubject `yaml:"subject"`
		RSABits *int            `yaml:"rsaBits"`
	} `yaml:"defaults"`
	Requests []struct {
		Name    string          `yaml:"name"`
		Subject csrBatchSubject `yaml:"subject"`
		RSABits *int            `yaml:"rsaBits"`
		SAN     struct {
			DNS []string `yaml:"dns"`
			IP  []string `yaml:"ip"`
		} `yaml:"san"`
		Key *struct {
			File         string `yaml:"file"`
			PasswordEnv  string `yaml:"passwordEnv"`
			PasswordFile string `yaml:"passwordFile"`
		} `yaml:"key"`
	} `yaml:"requests"`
}

func newCSRBatchCommand(stdout, stderr io.Writer) *cobra.Command {
	var config, outDir string
	var dryRun bool
	cmd := &cobra.Command{Use: "batch", Short: "Create multiple CSRs from YAML after validating the entire batch", Args: cobra.NoArgs,
		Example: "  ssl-toolbox csr batch --config requests.yaml --out-dir certificates --dry-run\n  ssl-toolbox csr batch --config requests.yaml --out-dir certificates",
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			plans, err := prepareCSRBatch(config, outDir, stderr)
			if err != nil {
				return err
			}
			if dryRun {
				return printCSRBatchPlan(plans, stdout)
			}
			completed := []string{}
			for _, plan := range plans {
				if err := writeCSR(plan); err != nil {
					return fmt.Errorf("request %q failed; completed requests: [%s]: %w", plan.options.name, strings.Join(completed, ", "), err)
				}
				completed = append(completed, plan.options.name)
				if err := printCSRCreated(plan, stdout); err != nil {
					return fmt.Errorf("reporting failed; completed requests: [%s]: %w", strings.Join(completed, ", "), err)
				}
			}
			_, err = fmt.Fprintf(stdout, "Completed %d CSR requests: %s\n", len(completed), strings.Join(completed, ", "))
			return err
		},
	}
	cmd.Flags().StringVar(&config, "config", "", "YAML batch specification; key/password file paths are relative to this file")
	cmd.Flags().StringVar(&outDir, "out-dir", "", "Output directory, relative to the working directory; created only when generating")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Validate all requests and existing keys, then print a plan without generating keys or writing files")
	_ = cmd.MarkFlagRequired("config")
	_ = cmd.MarkFlagRequired("out-dir")
	return cmd
}

func prepareCSRBatch(path, outDir string, stderr io.Writer) ([]*csrPlan, error) {
	if strings.TrimSpace(path) == "" || strings.TrimSpace(outDir) == "" {
		return nil, errors.New("--config and --out-dir must not be empty")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CSR batch config: %w", err)
	}
	var tree yaml.Node
	if err := yaml.Unmarshal(data, &tree); err != nil {
		return nil, fmt.Errorf("parse CSR batch YAML: %w", err)
	}
	if err := validateYAML(&tree); err != nil {
		return nil, err
	}
	if err := validateCSRBatchYAML(&tree); err != nil {
		return nil, err
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var batch csrBatchConfig
	if err := decoder.Decode(&batch); err != nil {
		return nil, fmt.Errorf("decode CSR batch config: %w", err)
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, errors.New("CSR batch config must contain exactly one YAML document")
	}
	if len(batch.Requests) == 0 {
		return nil, errors.New("CSR batch config must contain at least one request")
	}
	if batch.Defaults.Subject.CommonName != nil {
		return nil, errors.New("commonName must be specified per request, not in defaults")
	}
	base, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	relativeFile := func(path string) string {
		if path != "" && !filepath.IsAbs(path) {
			return filepath.Join(base, path)
		}
		return path
	}
	plans := []*csrPlan{}
	names := map[string]bool{}
	for i, request := range batch.Requests {
		if strings.TrimSpace(request.Name) == "" {
			return nil, fmt.Errorf("request %d: name is required", i+1)
		}
		name := strings.ToLower(request.Name)
		if names[name] {
			return nil, fmt.Errorf("duplicate request name %q (names must be unique ignoring case)", request.Name)
		}
		names[name] = true
		if request.Subject.CommonName == nil || strings.TrimSpace(*request.Subject.CommonName) == "" {
			return nil, fmt.Errorf("request %q: subject.commonName is required", request.Name)
		}
		o := csrOptions{outDir: outDir, name: request.Name, bits: 4096, dns: request.SAN.DNS, ips: request.SAN.IP}
		applyCSRBatchSubject(&o, batch.Defaults.Subject)
		applyCSRBatchSubject(&o, request.Subject)
		if batch.Defaults.RSABits != nil {
			o.bits = *batch.Defaults.RSABits
		}
		if request.RSABits != nil {
			o.bits = *request.RSABits
		}
		if request.Key != nil {
			if strings.TrimSpace(request.Key.File) == "" {
				return nil, fmt.Errorf("request %q: key.file must not be empty", request.Name)
			}
			if request.RSABits != nil {
				return nil, fmt.Errorf("request %q: key and rsaBits cannot be combined", request.Name)
			}
			if err := validatePasswordSource(request.Key.PasswordEnv, request.Key.PasswordFile); err != nil {
				return nil, fmt.Errorf("request %q: %w", request.Name, err)
			}
			o.keyFile = relativeFile(request.Key.File)
			o.keyPassEnv = request.Key.PasswordEnv
			o.keyPassFile = relativeFile(request.Key.PasswordFile)
		}
		plan, err := prepareCSR(o, stderr)
		if err != nil {
			return nil, fmt.Errorf("request %q: %w", request.Name, err)
		}
		plans = append(plans, plan)
	}
	return plans, nil
}

func applyCSRBatchSubject(o *csrOptions, subject csrBatchSubject) {
	for _, field := range []struct {
		value *string
		dest  *string
	}{{subject.CommonName, &o.cn}, {subject.Country, &o.country}, {subject.Province, &o.province}, {subject.Locality, &o.locality}, {subject.Organization, &o.organization}, {subject.OrganizationalUnit, &o.unit}, {subject.Email, &o.email}} {
		if field.value != nil {
			*field.dest = *field.value
		}
	}
}

func validateCSRBatchYAML(node *yaml.Node) error {
	if node.Kind == yaml.AliasNode || node.Tag == "!!merge" {
		return errors.New("CSR batch YAML aliases and merge keys are unsupported; use defaults")
	}
	if node.Tag == "!!null" {
		return errors.New("CSR batch YAML null values are unsupported; omit a field to inherit or use an empty string to clear it")
	}
	for _, child := range node.Content {
		if err := validateCSRBatchYAML(child); err != nil {
			return err
		}
	}
	return nil
}

func printCSRBatchPlan(plans []*csrPlan, stdout io.Writer) error {
	var out bytes.Buffer
	fmt.Fprintf(&out, "CSR batch plan: %d requests (dry-run; no files written)\n", len(plans))
	for _, plan := range plans {
		subject := plan.template.Subject
		subject.ExtraNames = nil // Show the emailAddress separately as readable text.
		fmt.Fprintf(&out, "\n[%s]\n  Subject: %s\n", plan.options.name, subject.String())
		if plan.options.email != "" {
			fmt.Fprintf(&out, "  Subject emailAddress: %s\n", plan.options.email)
		}
		fmt.Fprintf(&out, "  SAN: %s\n", strings.Join(inspectionAlternativeNames(plan.template.DNSNames, nil, plan.template.IPAddresses, nil), ", "))
		if plan.options.keyFile == "" {
			fmt.Fprintf(&out, "  Key: generate RSA %d bits (unencrypted PKCS#8)\n  Key output: %s\n", plan.options.bits, plan.keyPath)
		} else {
			fmt.Fprintf(&out, "  Key: reuse %s (RSA %d bits; validated)\n", plan.options.keyFile, plan.key.N.BitLen())
		}
		fmt.Fprintf(&out, "  Signature: SHA256-RSA\n  CSR output: %s\n", plan.csrPath)
	}
	_, err := io.Copy(stdout, &out)
	return err
}
