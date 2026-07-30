package calculator

import (
	"testing"

	"mdsri-engine/internal/models"
)

func TestCalculateToolScore(t *testing.T) {
	counts := models.SeverityCounts{
		Critical: 2,
		High:     3,
		Medium:   4,
		Low:      5,
	}

	weights := models.SeverityWeights{
		Critical: 4.0,
		High:     2.0,
		Medium:   1.0,
		Low:      0.25,
	}

	// Calculation: 2*4.0 + 3*2.0 + 4*1.0 + 5*0.25 = 8.0 + 6.0 + 4.0 + 1.25 = 19.25
	expected := 19.25
	actual := CalculateToolScore(counts, weights)

	if actual != expected {
		t.Errorf("Expected score %f, got %f", expected, actual)
	}
}

func TestCalculateMDSRI(t *testing.T) {
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
	}

	// Sonar (SAST): Crit 1, High 0, Med 1, Low 0 -> 1*4 + 0*2 + 1*1 + 0*0.25 = 5.0
	sonar := &models.ToolReport{
		ToolName: "SonarQube",
		Category: "SAST",
		Counts: models.SeverityCounts{
			Critical: 1,
			Medium:   1,
		},
	}

	// Dependency (SCA): Crit 0, High 1, Med 2, Low 0 -> 0*4 + 1*2 + 2*1 + 0*0.25 = 4.0
	dependency := &models.ToolReport{
		ToolName: "DependencyCheck",
		Category: "SCA",
		Counts: models.SeverityCounts{
			High:   1,
			Medium: 2,
		},
	}

	// Trivy (Container): Crit 0, High 0, Med 0, Low 4 -> 4*0.25 = 1.0
	trivy := &models.ToolReport{
		ToolName: "Trivy",
		Category: "Container",
		Counts: models.SeverityCounts{
			Low: 4,
		},
	}

	// Expected MD-SRI: (5.0 * 0.3) + (4.0 * 0.3) + (1.0 * 0.4) = 1.5 + 1.2 + 0.4 = 3.1
	expectedMDSRI := 3.1

	actualMDSRI, details := CalculateMDSRI(sonar, dependency, trivy, config)

	if actualMDSRI != expectedMDSRI {
		t.Errorf("Expected MD-SRI %f, got %f", expectedMDSRI, actualMDSRI)
	}

	if details.SASTScore != 5.0 {
		t.Errorf("Expected SAST Score 5.0, got %f", details.SASTScore)
	}

	if details.SCAScore != 4.0 {
		t.Errorf("Expected SCA Score 4.0, got %f", details.SCAScore)
	}

	if details.ContainerScore != 1.0 {
		t.Errorf("Expected Container Score 1.0, got %f", details.ContainerScore)
	}
}
