package parser

import (
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
