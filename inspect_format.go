package main

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"strings"
	"time"
)

func applyExpiryStatus(report *inspectionReport, now time.Time, warningDays int) {
	report.ExpiryWarningDays = warningDays
	for i := range report.Entries {
		cert := report.Entries[i].Certificate
		if cert == nil {
			continue
		}
		remaining := cert.NotAfter.Sub(now)
		cert.ExpiresInSeconds = int64(remaining.Seconds())
		switch {
		case !now.Before(cert.NotAfter):
			cert.Validity = "expired"
		case now.Before(cert.NotBefore):
			cert.Validity = "not yet valid"
		case warningDays > 0 && remaining.Hours()/24 <= float64(warningDays):
			cert.Validity = "expiring soon"
		default:
			cert.Validity = "valid by dates"
		}
	}
}

func printInspection(w io.Writer, report *inspectionReport) error {
	return printInspectionColored(w, report, false)
}

func printInspectionColored(w io.Writer, report *inspectionReport, color bool) error {
	var out bytes.Buffer
	paint := func(s, code string) string { return paintANSI(s, code, color) }
	field := func(indent, label, value string) {
		fmt.Fprintf(&out, "%s%s %s\n", indent, paint(label+":", "36"), value)
	}
	field("", "File", paint(report.File, "1"))
	field("", "Format", paint(report.Format, "1;36"))
	if report.StoreVersion > 0 {
		field("", "Store version", fmt.Sprint(report.StoreVersion))
	}
	integrityCode := "33"
	if report.Integrity == "verified" {
		integrityCode = "32"
	}
	field("", "Integrity", paint(report.Integrity, integrityCode))
	field("", "Entries", fmt.Sprintf("%d (certificates: %d; private keys: %d; public keys: %d)", report.EntryCount, report.CertificateCount, report.PrivateKeyCount, report.PublicKeyCount))
	expired, soon, future := 0, 0, 0
	for _, e := range report.Entries {
		if e.Certificate != nil {
			switch e.Certificate.Validity {
			case "expired":
				expired++
			case "expiring soon":
				soon++
			case "not yet valid":
				future++
			}
		}
	}
	field("", "Certificate dates", fmt.Sprintf("%s; %s; %s", paint(fmt.Sprintf("%d EXPIRED", expired), statusCountColor(expired, "1;31")), paint(fmt.Sprintf("%d EXPIRING SOON (within %d days)", soon, report.ExpiryWarningDays), statusCountColor(soon, "1;33")), paint(fmt.Sprintf("%d NOT YET VALID", future), statusCountColor(future, "1;33"))))
	if report.MAC != nil {
		field("", "MAC/digest", protectionText(*report.MAC))
	}
	for i, p := range report.Encryption {
		field("", fmt.Sprintf("Encrypted safe %d", i+1), protectionText(p))
	}
	for _, entry := range report.Entries {
		code := "1;36"
		if entry.Type == "private key" {
			code = "1;33"
		} else if entry.Type == "trusted certificate" {
			code = "1;34"
		}
		fmt.Fprintf(&out, "\n%s\n", paint(fmt.Sprintf("[%s] %s", entry.ID, entry.Type), code))
		if entry.Alias != "" {
			field("  ", "Alias", paint(entry.Alias, "1"))
		}
		if entry.LocalKeyID != "" {
			field("  ", "Local key ID", paint(entry.LocalKeyID, "2"))
		}
		if entry.Created != nil {
			field("  ", "Created", entry.Created.UTC().Format(time.RFC3339))
		}
		if entry.Protection != nil {
			field("  ", "Protection", protectionText(*entry.Protection))
		}
		if key := entry.PublicKey; key != nil {
			value := fmt.Sprintf("%s, %d bits", key.Algorithm, key.Bits)
			if key.Curve != "" {
				value += " (" + key.Curve + ")"
			}
			field("  ", "Public key", value)
			field("  ", "SPKI SHA-256", paint(key.SHA256, "2"))
		}
		if len(entry.Matches) > 0 {
			field("  ", "Matching entries", paint(strings.Join(entry.Matches, ", "), "1;35"))
		}
		if cert := entry.Certificate; cert != nil {
			field("  ", "Subject", paint(cert.Subject, "1"))
			field("  ", "Issuer", cert.Issuer)
			field("  ", "Serial", cert.Serial)
			field("  ", "X.509 version", fmt.Sprint(cert.Version))
			field("  ", "Valid from", cert.NotBefore.UTC().Format(time.RFC3339))
			status, code := "VALID BY DATES", "32"
			switch cert.Validity {
			case "expired":
				status, code = "EXPIRED", "1;31"
			case "expiring soon":
				status, code = "EXPIRING SOON", "1;33"
			case "not yet valid":
				status, code = "NOT YET VALID", "1;33"
			}
			field("  ", "Valid until", paint(cert.NotAfter.UTC().Format(time.RFC3339), code))
			field("  ", "Date status", paint(status, code))
			days := int64(math.Ceil(math.Abs(float64(cert.ExpiresInSeconds)) / 86400))
			expiry := fmt.Sprintf("in %d days", days)
			if days <= 1 {
				expiry = "in less than 1 day"
			}
			if cert.Validity == "expired" {
				expiry = fmt.Sprintf("%d days ago", days)
				if days <= 1 {
					expiry = "less than 1 day ago"
				}
			}
			field("  ", "Expiry", paint(expiry, code))
			field("  ", "Signature", cert.SignatureAlgorithm)
			field("  ", "Certificate SHA-256", paint(cert.SHA256, "2"))
			field("  ", "CA", fmt.Sprintf("%t; basic constraints: %t; self-signed: %t", cert.IsCA, cert.BasicConstraintsValid, cert.SelfSigned))
			if cert.MaxPathLen != nil {
				field("  ", "Maximum CA path length", fmt.Sprint(*cert.MaxPathLen))
			}
			field("  ", "Key usage", strings.Join(cert.KeyUsage, ", "))
			field("  ", "Extended key usage", strings.Join(cert.ExtendedKeyUsage, ", "))
			field("  ", "SAN", strings.Join(cert.SAN, ", "))
			if len(cert.UnhandledCriticalExtensions) > 0 {
				field("  ", "Unhandled critical extensions", paint(strings.Join(cert.UnhandledCriticalExtensions, ", "), "1;33"))
			}
		}
	}
	fmt.Fprintln(&out, "\n"+paint("Certificate date status does not verify a chain against a trusted root or check revocation.", "2"))
	_, err := io.Copy(w, &out)
	return err
}

func statusCountColor(count int, warning string) string {
	if count > 0 {
		return warning
	}
	return "2"
}
