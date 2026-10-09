package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExpiryStatusBoundaries(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	for _, tt := range []struct {
		name          string
		before, after time.Time
		days          int
		want          string
	}{
		{"expired", now.Add(-time.Hour), now.Add(-time.Second), 30, "expired"},
		{"expiry instant", now.Add(-time.Hour), now, 30, "expired"},
		{"soon boundary", now.Add(-time.Hour), now.Add(30 * 24 * time.Hour), 30, "expiring soon"},
		{"outside boundary", now.Add(-time.Hour), now.Add(30*24*time.Hour + time.Second), 30, "valid by dates"},
		{"not yet", now.Add(time.Hour), now.Add(24 * time.Hour), 30, "not yet valid"},
		{"disabled", now.Add(-time.Hour), now.Add(time.Hour), 0, "valid by dates"},
		{"custom", now.Add(-time.Hour), now.Add(45 * 24 * time.Hour), 60, "expiring soon"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := &inspectionReport{Entries: []inspectionEntry{{Certificate: &certificateDetails{NotBefore: tt.before, NotAfter: tt.after}}}}
			applyExpiryStatus(r, now, tt.days)
			c := r.Entries[0].Certificate
			if c.Validity != tt.want || c.ExpiresInSeconds != int64(tt.after.Sub(now).Seconds()) || r.ExpiryWarningDays != tt.days {
				t.Fatalf("unexpected status: %+v", c)
			}
		})
	}
}

func TestInspectionColorsAndJSON(t *testing.T) {
	_, cert, _ := fixture(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "cert.der")
	if err := os.WriteFile(path, cert.Raw, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NO_COLOR", "1")
	t.Setenv("TERM", "dumb")
	for _, mode := range []string{"auto", "never", "always"} {
		var output bytes.Buffer
		if err := run([]string{"inspect", path, "--color", mode}, &output, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(output.String(), "\x1b[") != (mode == "always") {
			t.Fatalf("incorrect color mode %s", mode)
		}
		for _, anchor := range []string{"[entry-1] certificate", "EXPIRING SOON", "Certificate dates:", "Subject:"} {
			if !strings.Contains(output.String(), anchor) {
				t.Fatalf("missing %s", anchor)
			}
		}
	}
	var output bytes.Buffer
	if err := run([]string{"inspect", path, "--color", "always", "--json", "--expiry-warning-days", "0"}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var r inspectionReport
	if err := json.Unmarshal(output.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "\x1b[") || r.Entries[0].Certificate.Validity != "valid by dates" || r.ExpiryWarningDays != 0 {
		t.Fatal("JSON color or threshold incorrect")
	}
	for _, args := range [][]string{{"inspect", path, "--color", "invalid"}, {"inspect", path, "--expiry-warning-days", "-1"}} {
		if err := run(args, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
			t.Fatal("accepted invalid display option")
		}
	}
	// Critical states retain explicit labels without ANSI.
	r.Entries[0].Certificate.Validity = "expired"
	var plain, colored bytes.Buffer
	if err := printInspectionColored(&plain, &r, false); err != nil {
		t.Fatal(err)
	}
	if err := printInspectionColored(&colored, &r, true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plain.String(), "1 EXPIRED") || !strings.Contains(colored.String(), "\x1b[1;31mEXPIRED") {
		t.Fatal("expiry is not prominent")
	}
}
