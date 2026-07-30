package parser

import (
	"encoding/json"
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
