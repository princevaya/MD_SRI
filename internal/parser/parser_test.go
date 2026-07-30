package parser

import (
	"os"
	"testing"
)

func TestParseSonarQube(t *testing.T) {
	report, err := ParseSonarQube("../../reports/sonar.json")
	if err != nil {
		t.Fatalf("Failed to parse SonarQube report: %v", err)
	}

	if report.ToolName != "SonarQube" {
		t.Errorf("Expected tool name SonarQube, got %s", report.ToolName)
	}

	if report.Category != "SAST" {
		t.Errorf("Expected category SAST, got %s", report.Category)
	}

	// Expected based on reports/sonar.json:
	// 1 blocker -> Critical
	// 1 critical -> High
	// 1 major -> Medium
	// 1 minor, 1 info -> Low (total 2)
	if report.Counts.Critical != 1 {
		t.Errorf("Expected 1 critical issue, got %d", report.Counts.Critical)
	}
	if report.Counts.High != 1 {
		t.Errorf("Expected 1 high issue, got %d", report.Counts.High)
	}
	if report.Counts.Medium != 1 {
		t.Errorf("Expected 1 medium issue, got %d", report.Counts.Medium)
	}
	if report.Counts.Low != 2 {
		t.Errorf("Expected 2 low issues, got %d", report.Counts.Low)
	}
}

func TestParseSonarQubeBytes(t *testing.T) {
	data, err := os.ReadFile("../../reports/sonar.json")
	if err != nil {
		t.Fatalf("Failed to read SonarQube report: %v", err)
	}

	report, err := ParseSonarQubeBytes(data)
	if err != nil {
		t.Fatalf("ParseSonarQubeBytes failed: %v", err)
	}

	if report.Counts.Critical != 1 || report.Counts.High != 1 || report.Counts.Medium != 1 || report.Counts.Low != 2 {
		t.Errorf("Incorrect counts in parsed bytes report: %+v", report.Counts)
	}
}

func TestParseDependencyCheck(t *testing.T) {
	report, err := ParseDependencyCheck("../../reports/dependency.json")
	if err != nil {
		t.Fatalf("Failed to parse Dependency Check report: %v", err)
	}

	if report.ToolName != "OWASP Dependency Check" {
		t.Errorf("Expected tool name OWASP Dependency Check, got %s", report.ToolName)
	}

	if report.Category != "SCA" {
		t.Errorf("Expected category SCA, got %s", report.Category)
	}

	// Expected based on reports/dependency.json:
	// 1 CRITICAL -> Critical
	// 1 HIGH -> High
	// 1 MEDIUM -> Medium
	// 1 LOW -> Low
	if report.Counts.Critical != 1 {
		t.Errorf("Expected 1 critical issue, got %d", report.Counts.Critical)
	}
	if report.Counts.High != 1 {
		t.Errorf("Expected 1 high issue, got %d", report.Counts.High)
	}
	if report.Counts.Medium != 1 {
		t.Errorf("Expected 1 medium issue, got %d", report.Counts.Medium)
	}
	if report.Counts.Low != 1 {
		t.Errorf("Expected 1 low issue, got %d", report.Counts.Low)
	}
}

func TestParseDependencyCheckBytes(t *testing.T) {
	data, err := os.ReadFile("../../reports/dependency.json")
	if err != nil {
		t.Fatalf("Failed to read Dependency Check report: %v", err)
	}

	report, err := ParseDependencyCheckBytes(data)
	if err != nil {
		t.Fatalf("ParseDependencyCheckBytes failed: %v", err)
	}

	if report.Counts.Critical != 1 || report.Counts.High != 1 || report.Counts.Medium != 1 || report.Counts.Low != 1 {
		t.Errorf("Incorrect counts in parsed bytes report: %+v", report.Counts)
	}
}

func TestParseTrivy(t *testing.T) {
	report, err := ParseTrivy("../../reports/trivy.json")
	if err != nil {
		t.Fatalf("Failed to parse Trivy report: %v", err)
	}

	if report.ToolName != "Trivy" {
		t.Errorf("Expected tool name Trivy, got %s", report.ToolName)
	}

	if report.Category != "Container" {
		t.Errorf("Expected category Container, got %s", report.Category)
	}

	// Expected based on reports/trivy.json:
	// 1 CRITICAL -> Critical
	// 1 HIGH -> High
	// 1 MEDIUM -> Medium
	// 1 LOW -> Low
	if report.Counts.Critical != 1 {
		t.Errorf("Expected 1 critical issue, got %d", report.Counts.Critical)
	}
	if report.Counts.High != 1 {
		t.Errorf("Expected 1 high issue, got %d", report.Counts.High)
	}
	if report.Counts.Medium != 1 {
		t.Errorf("Expected 1 medium issue, got %d", report.Counts.Medium)
	}
	if report.Counts.Low != 1 {
		t.Errorf("Expected 1 low issue, got %d", report.Counts.Low)
	}
}

func TestParseTrivyBytes(t *testing.T) {
	data, err := os.ReadFile("../../reports/trivy.json")
	if err != nil {
		t.Fatalf("Failed to read Trivy report: %v", err)
	}

	report, err := ParseTrivyBytes(data)
	if err != nil {
		t.Fatalf("ParseTrivyBytes failed: %v", err)
	}

	if report.Counts.Critical != 1 || report.Counts.High != 1 || report.Counts.Medium != 1 || report.Counts.Low != 1 {
		t.Errorf("Incorrect counts in parsed bytes report: %+v", report.Counts)
	}
}

func TestParseDependencyCheckXML(t *testing.T) {
	report, err := ParseDependencyCheck("../../reports/dependency-check-report.xml")
	if err != nil {
		t.Fatalf("Failed to parse Dependency Check XML: %v", err)
	}

	if report.ToolName != "OWASP Dependency Check" {
		t.Errorf("Expected tool name OWASP Dependency Check, got %s", report.ToolName)
	}

	// Expected based on reports/dependency-check-report.xml:
	// 1 CRITICAL -> Critical
	// 1 HIGH -> High
	// 1 MEDIUM -> Medium
	// 1 LOW + 1 UNKNOWN -> Low (total 2)
	if report.Counts.Critical != 1 {
		t.Errorf("Expected 1 critical issue, got %d", report.Counts.Critical)
	}
	if report.Counts.High != 1 {
		t.Errorf("Expected 1 high issue, got %d", report.Counts.High)
	}
	if report.Counts.Medium != 1 {
		t.Errorf("Expected 1 medium issue, got %d", report.Counts.Medium)
	}
	if report.Counts.Low != 2 {
		t.Errorf("Expected 2 low issues (Low+Unknown), got %d", report.Counts.Low)
	}

	// Verify packagePath is mapped as component when available
	foundPackagePath := false
	for _, f := range report.Findings {
		if f.ID == "CVE-2022-22965" && f.Component == "org.springframework:spring-core:5.3.8" {
			foundPackagePath = true
		}
	}
	if !foundPackagePath {
		t.Errorf("Expected finding component to fall back to packagePath when available")
	}
}

func TestParseDependencyCheckXMLBytes(t *testing.T) {
	data, err := os.ReadFile("../../reports/dependency-check-report.xml")
	if err != nil {
		t.Fatalf("Failed to read XML dependency report: %v", err)
	}

	report, err := ParseDependencyCheckBytes(data)
	if err != nil {
		t.Fatalf("ParseDependencyCheckBytes failed on XML content: %v", err)
	}

	if report.Counts.Critical != 1 || report.Counts.High != 1 || report.Counts.Medium != 1 || report.Counts.Low != 2 {
		t.Errorf("Incorrect counts in XML parsed bytes: %+v", report.Counts)
	}
}
