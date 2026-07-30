package parser

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"strings"

	"mdsri-engine/internal/models"
)

// SonarQube JSON schema mapping
type sonarIssue struct {
	Key       string `json:"key"`
	Rule      string `json:"rule"`
	Severity  string `json:"severity"`
	Component string `json:"component"`
	Message   string `json:"message"`
	Type      string `json:"type"`
}

type sonarResponse struct {
	Issues []sonarIssue `json:"issues"`
}

// ParseSonarQubeBytes parses SonarQube JSON issues from raw bytes.
func ParseSonarQubeBytes(data []byte) (*models.ToolReport, error) {
	var resp sonarResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal SonarQube JSON: %w", err)
	}

	report := &models.ToolReport{
		ToolName: "SonarQube",
		Category: "SAST",
		Findings: make([]models.Finding, 0),
	}

	for _, issue := range resp.Issues {
		var sev models.Severity
		switch strings.ToUpper(issue.Severity) {
		case "BLOCKER":
			sev = models.SeverityCritical
			report.Counts.Critical++
		case "CRITICAL":
			sev = models.SeverityHigh
			report.Counts.High++
		case "MAJOR":
			sev = models.SeverityMedium
			report.Counts.Medium++
		case "MINOR", "INFO":
			sev = models.SeverityLow
			report.Counts.Low++
		default:
			sev = models.SeverityLow
			report.Counts.Low++
		}

		report.Findings = append(report.Findings, models.Finding{
			ID:          issue.Key,
			Title:       issue.Rule,
			Description: issue.Message,
			Severity:    sev,
			Component:   issue.Component,
			Source:      issue.Type,
		})
	}

	return report, nil
}

// ParseSonarQube parses SonarQube JSON issues file.
func ParseSonarQube(path string) (*models.ToolReport, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open SonarQube report: %w", err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read SonarQube report: %w", err)
	}

	return ParseSonarQubeBytes(data)
}

// OWASP Dependency Check JSON schema mapping
type depVulnerability struct {
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

type depDependency struct {
	FileName        string             `json:"fileName"`
	Vulnerabilities []depVulnerability `json:"vulnerabilities"`
}

type depResponse struct {
	Dependencies []depDependency `json:"dependencies"`
}

// OWASP Dependency Check XML schema mapping
type xmlVulnerability struct {
	Name        string `xml:"name"`
	Severity    string `xml:"severity"`
	Description string `xml:"description"`
}

type xmlDependency struct {
	FileName        string             `xml:"fileName"`
	FilePath        string             `xml:"filePath"`
	PackagePath     string             `xml:"packagePath"`
	Vulnerabilities []xmlVulnerability `xml:"vulnerabilities>vulnerability"`
}

type xmlAnalysis struct {
	XMLName      xml.Name        `xml:"analysis"`
	Dependencies []xmlDependency `xml:"dependencies>dependency"`
}

// getFirstNonWhitespace returns the first non-whitespace character in the byte slice.
func getFirstNonWhitespace(data []byte) byte {
	for _, b := range data {
		if b == ' ' || b == '\t' || b == '\r' || b == '\n' {
			continue
		}
		return b
	}
	return 0
}

// ParseDependencyCheckJSONBytes parses OWASP Dependency Check JSON from raw bytes.
func ParseDependencyCheckJSONBytes(data []byte) (*models.ToolReport, error) {
	var resp depResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal Dependency Check JSON: %w", err)
	}

	report := &models.ToolReport{
		ToolName: "OWASP Dependency Check",
		Category: "SCA",
		Findings: make([]models.Finding, 0),
	}

	for _, dep := range resp.Dependencies {
		for _, vuln := range dep.Vulnerabilities {
			var sev models.Severity
			switch strings.ToUpper(vuln.Severity) {
			case "CRITICAL":
				sev = models.SeverityCritical
				report.Counts.Critical++
			case "HIGH":
				sev = models.SeverityHigh
				report.Counts.High++
			case "MEDIUM":
				sev = models.SeverityMedium
				report.Counts.Medium++
			case "LOW":
				sev = models.SeverityLow
				report.Counts.Low++
			default:
				sev = models.SeverityLow
				report.Counts.Low++
			}

			report.Findings = append(report.Findings, models.Finding{
				ID:          vuln.Name,
				Title:       vuln.Name,
				Description: vuln.Description,
				Severity:    sev,
				Component:   dep.FileName,
				Source:      "Dependency",
			})
		}
	}

	return report, nil
}

// ParseDependencyCheckXMLBytes parses OWASP Dependency Check XML from raw bytes.
func ParseDependencyCheckXMLBytes(data []byte) (*models.ToolReport, error) {
	var analysis xmlAnalysis
	if err := xml.Unmarshal(data, &analysis); err != nil {
		return nil, fmt.Errorf("failed to unmarshal Dependency Check XML: %w", err)
	}

	report := &models.ToolReport{
		ToolName: "OWASP Dependency Check",
		Category: "SCA",
		Findings: make([]models.Finding, 0),
	}

	for _, dep := range analysis.Dependencies {
		component := dep.PackagePath
		if component == "" {
			component = dep.FileName
		}

		for _, vuln := range dep.Vulnerabilities {
			var sev models.Severity
			switch strings.ToUpper(vuln.Severity) {
			case "CRITICAL":
				sev = models.SeverityCritical
				report.Counts.Critical++
			case "HIGH":
				sev = models.SeverityHigh
				report.Counts.High++
			case "MEDIUM":
				sev = models.SeverityMedium
				report.Counts.Medium++
			case "LOW", "UNKNOWN":
				sev = models.SeverityLow
				report.Counts.Low++
			default:
				sev = models.SeverityLow
				report.Counts.Low++
			}

			report.Findings = append(report.Findings, models.Finding{
				ID:          vuln.Name,
				Title:       vuln.Name,
				Description: vuln.Description,
				Severity:    sev,
				Component:   component,
				Source:      "Dependency",
			})
		}
	}

	return report, nil
}

// ParseDependencyCheckBytes auto-detects and parses OWASP Dependency Check JSON or XML from raw bytes.
func ParseDependencyCheckBytes(data []byte) (*models.ToolReport, error) {
	first := getFirstNonWhitespace(data)
	if first == '{' || first == '[' {
		return ParseDependencyCheckJSONBytes(data)
	} else if first == '<' {
		return ParseDependencyCheckXMLBytes(data)
	}
	return nil, fmt.Errorf("unknown dependency check report format: starting byte '%c'", first)
}

// ParseDependencyCheck parses OWASP Dependency Check JSON file.
func ParseDependencyCheck(path string) (*models.ToolReport, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open Dependency Check report: %w", err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read Dependency Check report: %w", err)
	}

	return ParseDependencyCheckBytes(data)
}

// Trivy JSON schema mapping
type trivyVulnerability struct {
	VulnerabilityID string `json:"VulnerabilityID"`
	PkgName         string `json:"PkgName"`
	Severity        string `json:"Severity"`
	Title           string `json:"Title"`
	Description     string `json:"Description"`
}

type trivyResult struct {
	Target          string               `json:"Target"`
	Vulnerabilities []trivyVulnerability `json:"Vulnerabilities"`
}

type trivyResponse struct {
	Results []trivyResult `json:"Results"`
}

// ParseTrivyBytes parses Trivy JSON from raw bytes.
func ParseTrivyBytes(data []byte) (*models.ToolReport, error) {
	var resp trivyResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal Trivy JSON: %w", err)
	}

	report := &models.ToolReport{
		ToolName: "Trivy",
		Category: "Container",
		Findings: make([]models.Finding, 0),
	}

	for _, result := range resp.Results {
		for _, vuln := range result.Vulnerabilities {
			var sev models.Severity
			switch strings.ToUpper(vuln.Severity) {
			case "CRITICAL":
				sev = models.SeverityCritical
				report.Counts.Critical++
			case "HIGH":
				sev = models.SeverityHigh
				report.Counts.High++
			case "MEDIUM":
				sev = models.SeverityMedium
				report.Counts.Medium++
			case "LOW":
				sev = models.SeverityLow
				report.Counts.Low++
			default:
				sev = models.SeverityLow
				report.Counts.Low++
			}

			title := vuln.Title
			if title == "" {
				title = vuln.VulnerabilityID
			}

			report.Findings = append(report.Findings, models.Finding{
				ID:          vuln.VulnerabilityID,
				Title:       title,
				Description: vuln.Description,
				Severity:    sev,
				Component:   result.Target,
				Source:      vuln.PkgName,
			})
		}
	}

	return report, nil
}

// ParseTrivy parses Trivy JSON file.
func ParseTrivy(path string) (*models.ToolReport, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open Trivy report: %w", err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read Trivy report: %w", err)
	}

	return ParseTrivyBytes(data)
}
