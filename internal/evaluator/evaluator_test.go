package evaluator

import (
	"testing"

	"mdsri-engine/internal/models"
)

func TestEvaluatePolicy_Pass(t *testing.T) {
	config := &models.Config{
		SeverityWeights: models.SeverityWeights{
			Critical: 4.0,
			High:     2.0,
			Medium:   1.0,
			Low:      0.25,
		},
		CategoryWeights: models.CategoryWeights{
			SAST:      0.30,
			SCA:       0.30,
			Container: 0.40,
		},
		Environments: map[string]models.EnvPolicy{
			"production": {Threshold: 8.0},
		},
		VetoPolicies: models.VetoPolicies{
			VetoOnCritical: true,
			VetoOnHigh:     false,
		},
	}

	// Sonar: High 1 -> 2.0
	sonar := &models.ToolReport{
		ToolName: "SonarQube",
		Category: "SAST",
		Counts: models.SeverityCounts{
			High: 1,
		},
	}

	// Dependency: Med 2 -> 2.0
	dependency := &models.ToolReport{
		ToolName: "DependencyCheck",
		Category: "SCA",
		Counts: models.SeverityCounts{
			Medium: 2,
		},
	}

	// Trivy: Low 4 -> 1.0
	trivy := &models.ToolReport{
		ToolName: "Trivy",
		Category: "Container",
		Counts: models.SeverityCounts{
			Low: 4,
		},
	}

	// MD-SRI: (2.0 * 0.3) + (2.0 * 0.3) + (1.0 * 0.4) = 0.6 + 0.6 + 0.4 = 1.6
	// 1.6 <= 8.0 -> PASS
	result, err := EvaluatePolicy("TestProject", "production", sonar, dependency, trivy, config)
	if err != nil {
		t.Fatalf("EvaluatePolicy returned error: %v", err)
	}

	if result.Decision != "PASS" {
		t.Errorf("Expected PASS, got %s. Reason: %s", result.Decision, result.Reason)
	}

	if result.VetoTriggered {
		t.Errorf("Expected veto not triggered, but got veto triggered")
	}

	// Verify MetricsSummary is populated correctly
	if result.Metrics.SASTScore != 2.0 {
		t.Errorf("Expected SASTScore 2.0, got %f", result.Metrics.SASTScore)
	}
	if result.Metrics.SCAScore != 2.0 {
		t.Errorf("Expected SCAScore 2.0, got %f", result.Metrics.SCAScore)
	}
	if result.Metrics.ContainerScore != 1.0 {
		t.Errorf("Expected ContainerScore 1.0, got %f", result.Metrics.ContainerScore)
	}
	if result.Metrics.Counts.Critical != 0 {
		t.Errorf("Expected 0 critical, got %d", result.Metrics.Counts.Critical)
	}
	if result.Metrics.Counts.High != 1 {
		t.Errorf("Expected 1 high, got %d", result.Metrics.Counts.High)
	}
	if result.Metrics.Counts.Medium != 2 {
		t.Errorf("Expected 2 medium, got %d", result.Metrics.Counts.Medium)
	}
	if result.Metrics.Counts.Low != 4 {
		t.Errorf("Expected 4 low, got %d", result.Metrics.Counts.Low)
	}
}

func TestEvaluatePolicy_BlockThreshold(t *testing.T) {
	config := &models.Config{
		SeverityWeights: models.SeverityWeights{
			Critical: 4.0,
			High:     2.0,
			Medium:   1.0,
			Low:      0.25,
		},
		CategoryWeights: models.CategoryWeights{
			SAST:      0.30,
			SCA:       0.30,
			Container: 0.40,
		},
		Environments: map[string]models.EnvPolicy{
			"production": {Threshold: 2.0}, // Low threshold
		},
		VetoPolicies: models.VetoPolicies{
			VetoOnCritical: true,
			VetoOnHigh:     false,
		},
	}

	// Sonar: High 4 -> 8.0
	sonar := &models.ToolReport{
		ToolName: "SonarQube",
		Category: "SAST",
		Counts: models.SeverityCounts{
			High: 4,
		},
	}

	dependency := &models.ToolReport{ToolName: "DependencyCheck", Category: "SCA"}
	trivy := &models.ToolReport{ToolName: "Trivy", Category: "Container"}

	// MD-SRI: 8.0 * 0.3 = 2.4
	// 2.4 > 2.0 -> BLOCK
	result, err := EvaluatePolicy("TestProject", "production", sonar, dependency, trivy, config)
	if err != nil {
		t.Fatalf("EvaluatePolicy returned error: %v", err)
	}

	if result.Decision != "BLOCK" {
		t.Errorf("Expected BLOCK, got %s", result.Decision)
	}

	if result.VetoTriggered {
		t.Errorf("Expected veto not triggered, but got veto triggered")
	}

	// Verify MetricsSummary is populated correctly
	if result.Metrics.SASTScore != 8.0 {
		t.Errorf("Expected SASTScore 8.0, got %f", result.Metrics.SASTScore)
	}
	if result.Metrics.Counts.High != 4 {
		t.Errorf("Expected 4 high, got %d", result.Metrics.Counts.High)
	}
}

func TestEvaluatePolicy_BlockVeto(t *testing.T) {
	config := &models.Config{
		SeverityWeights: models.SeverityWeights{
			Critical: 4.0,
			High:     2.0,
			Medium:   1.0,
			Low:      0.25,
		},
		CategoryWeights: models.CategoryWeights{
			SAST:      0.30,
			SCA:       0.30,
			Container: 0.40,
		},
		Environments: map[string]models.EnvPolicy{
			"production": {Threshold: 100.0}, // Very high threshold, should pass if not vetoed
		},
		VetoPolicies: models.VetoPolicies{
			VetoOnCritical: true,
			VetoOnHigh:     false,
		},
	}

	// Sonar: Crit 1 -> 4.0 (veto triggered!)
	sonar := &models.ToolReport{
		ToolName: "SonarQube",
		Category: "SAST",
		Counts: models.SeverityCounts{
			Critical: 1,
		},
	}

	dependency := &models.ToolReport{ToolName: "DependencyCheck", Category: "SCA"}
	trivy := &models.ToolReport{ToolName: "Trivy", Category: "Container"}

	result, err := EvaluatePolicy("TestProject", "production", sonar, dependency, trivy, config)
	if err != nil {
		t.Fatalf("EvaluatePolicy returned error: %v", err)
	}

	if result.Decision != "BLOCK" {
		t.Errorf("Expected BLOCK due to veto, got %s", result.Decision)
	}

	if !result.VetoTriggered {
		t.Errorf("Expected veto triggered to be true, got false")
	}

	// Verify MetricsSummary is populated correctly
	if result.Metrics.Counts.Critical != 1 {
		t.Errorf("Expected 1 critical, got %d", result.Metrics.Counts.Critical)
	}
}
