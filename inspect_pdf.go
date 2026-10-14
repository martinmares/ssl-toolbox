package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/go-pdf/fpdf"
	"golang.org/x/image/font/gofont/gobold"
	"golang.org/x/image/font/gofont/goregular"
)

var inspectionANSI = regexp.MustCompile(`\x1b\[([0-9;]*)m`)

//go:embed assets/fonts/LICENSE
var inspectionFontLicense []byte

func writeInspectionPDF(path string, report *inspectionReport) error {
	// Use the terminal formatter so every field and warning stays consistent.
	var text bytes.Buffer
	if err := printInspectionColored(&text, report, true); err != nil {
		return err
	}
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(15, 15, 15)
	pdf.SetAutoPageBreak(true, 18)
	pdf.AddUTF8FontFromBytes("Go", "", goregular.TTF)
	pdf.AddUTF8FontFromBytes("Go", "B", gobold.TTF)
	pdf.SetTitle("ssl-toolbox inspection report", true)
	pdf.SetCreator("ssl-toolbox", true)
	pdf.SetAttachments([]fpdf.Attachment{{Content: inspectionFontLicense, Filename: "Go-Fonts-LICENSE.txt", Description: "License for the embedded Go fonts"}})
	generated := time.Now().UTC().Format("2006-01-02 15:04:05 UTC")
	pdf.SetHeaderFunc(func() {
		pdf.SetFont("Go", "B", 16)
		pdf.SetTextColor(20, 65, 85)
		pdf.CellFormat(180, 8, "Certificate, key and CSR inspection", "", 1, "", false, 0, "")
		pdf.SetFont("Go", "", 8)
		pdf.SetTextColor(100, 100, 100)
		pdf.CellFormat(180, 5, "ssl-toolbox | Generated "+generated, "", 1, "", false, 0, "")
		pdf.Ln(5)
	})
	pdf.SetFooterFunc(func() {
		pdf.SetY(-12)
		pdf.SetFont("Go", "", 8)
		pdf.SetTextColor(100, 100, 100)
		pdf.CellFormat(180, 5, fmt.Sprintf("Generated: %s | Page %d", generated, pdf.PageNo()), "", 0, "R", false, 0, "")
	})
	pdf.AddPage()
	for _, line := range strings.Split(strings.TrimSuffix(text.String(), "\n"), "\n") {
		plain := inspectionANSI.ReplaceAllString(line, "")
		if plain == "" {
			pdf.Ln(3)
			continue
		}
		heading := strings.HasPrefix(plain, "[")
		if heading && pdf.GetY() > 245 {
			pdf.AddPage()
		}
		size := 9.0
		if heading {
			size = 11
		}
		setInspectionPDFStyle(pdf, "", size)
		start := 0
		for _, match := range inspectionANSI.FindAllStringSubmatchIndex(line, -1) {
			pdf.Write(4.8, line[start:match[0]])
			setInspectionPDFStyle(pdf, line[match[2]:match[3]], size)
			start = match[1]
		}
		pdf.Write(4.8, line[start:])
		pdf.Ln(5.5)
	}
	var output bytes.Buffer
	if err := pdf.Output(&output); err != nil {
		return fmt.Errorf("generate inspection PDF: %w", err)
	}
	return writeNewFile(path, output.Bytes())
}

func setInspectionPDFStyle(pdf *fpdf.Fpdf, codes string, size float64) {
	style := ""
	r, g, b := 35, 35, 35
	for _, code := range strings.Split(codes, ";") {
		switch code {
		case "1":
			style = "B"
		case "2":
			r, g, b = 100, 100, 100
		case "31":
			r, g, b = 180, 25, 35
		case "32":
			r, g, b = 20, 110, 60
		case "33":
			r, g, b = 145, 90, 0
		case "34":
			r, g, b = 35, 70, 150
		case "35":
			r, g, b = 120, 45, 135
		case "36":
			r, g, b = 0, 100, 120
		}
	}
	pdf.SetFont("Go", style, size)
	pdf.SetTextColor(r, g, b)
}
