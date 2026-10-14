package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestInspectPDFCommand(t *testing.T) {
	_, cert, _ := fixture(t)
	dir := t.TempDir()
	input := filepath.Join(dir, "certificate.der")
	output := filepath.Join(dir, "report.pdf")
	if err := os.WriteFile(input, cert.Raw, 0600); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	if err := run([]string{"inspect", input, "--pdf", output, "--color", "never"}, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(output)
	if err != nil || !bytes.HasPrefix(data, []byte("%PDF-")) || !bytes.Contains(data, []byte("%%EOF")) {
		t.Fatalf("invalid PDF: %v", err)
	}
	if !strings.Contains(stdout.String(), "PDF report written to ") || strings.Contains(stdout.String(), "Subject:") {
		t.Fatal("unexpected terminal output")
	}
	for _, args := range [][]string{
		{"inspect", input, "--pdf", output},
		{"inspect", input, "--pdf", input},
		{"inspect", input, "--pdf", ""},
		{"inspect", input, "--pdf", filepath.Join(dir, "unused.pdf"), "--json"},
	} {
		if err := run(args, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
			t.Fatalf("accepted unsafe/conflicting output: %v", args)
		}
	}
	unchanged, err := os.ReadFile(output)
	if err != nil || !bytes.Equal(data, unchanged) {
		t.Fatal("existing report changed")
	}
	unchanged, err = os.ReadFile(input)
	if err != nil || !bytes.Equal(cert.Raw, unchanged) {
		t.Fatal("input changed")
	}
}

func TestInspectionPDFPaginationAndUnicode(t *testing.T) {
	_, cert, _ := fixture(t)
	report := &inspectionReport{File: "certificates/client.pfx", Format: "PKCS#12", Integrity: "verified", ExpiryWarningDays: 30}
	for i := 1; i <= 12; i++ {
		if err := addCertificate(report, inspectionEntry{ID: fmt.Sprintf("entry-%d", i), Type: "certificate", Alias: fmt.Sprintf("Příliš žluťoučký kůň %d", i)}, cert); err != nil {
			t.Fatal(err)
		}
		detail := report.Entries[i-1].Certificate
		detail.Validity = "expired"
		detail.SAN = []string{"DNS:client.example.org", "IP:192.0.2.10", "IP:2001:db8::10", "URI:https://example.org/" + strings.Repeat("longpath", 60)}
	}
	path := filepath.Join(t.TempDir(), "report.pdf")
	if err := writeInspectionPDF(path, report); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(regexp.MustCompile(`/Type /Page\b`).FindAll(data, -1)) < 2 {
		t.Fatal("long report did not paginate")
	}
	// When available, an independent PDF reader checks the actual rendered text.
	reader, err := exec.LookPath("pdftotext")
	if err != nil {
		t.Log("pdftotext unavailable; independent text extraction omitted")
		return
	}
	text, err := exec.Command(reader, path, "-").Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Příliš žluťoučký kůň 12", "entry-12", "DNS:client.example.org", "IP:192.0.2.10", "IP:2001:db8::10", "EXPIRED", "revocation", "Page 2", "Generated:", "UTC"} {
		if !strings.Contains(string(text), want) {
			t.Fatalf("PDF reader did not find %q", want)
		}
	}
}
