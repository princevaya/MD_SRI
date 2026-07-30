package calculator

import (
	"fmt"
	"mdsri-engine/internal/models"
)

// CalculateToolScore computes the score for a single tool report based on configured severity weights.
func CalculateToolScore(counts models.SeverityCounts, weights models.SeverityWeights) float64 {
	return (float64(counts.Critical) * weights.Critical) +
		(float64(counts.High) * weights.High) +
		(float64(counts.Medium) * weights.Medium) +
		(float64(counts.Low) * weights.Low)
}

// CalculateMDSRI computes the overall index and fills in detailed calculation logs.
func CalculateMDSRI(sonar, dependency, trivy *models.ToolReport, config *models.Config) (float64, models.CalculationDetails) {
	// 1. Compute individual tool scores
	sonar.Score = CalculateToolScore(sonar.Counts, config.SeverityWeights)
	dependency.Score = CalculateToolScore(dependency.Counts, config.SeverityWeights)
	trivy.Score = CalculateToolScore(trivy.Counts, config.SeverityWeights)

	// 2. Compute category weighted scores
	sastWeighted := sonar.Score * config.CategoryWeights.SAST
	scaWeighted := dependency.Score * config.CategoryWeights.SCA
	containerWeighted := trivy.Score * config.CategoryWeights.Container

	// 3. Compute total MD-SRI
	mdsri := sastWeighted + scaWeighted + containerWeighted

	// 4. Build detailed formula string
	formula := fmt.Sprintf(
		"MD-SRI = (SAST Score [%.2f] * Weight [%.2f]) + (SCA Score [%.2f] * Weight [%.2f]) + (Container Score [%.2f] * Weight [%.2f]) = %.4f",
		sonar.Score, config.CategoryWeights.SAST,
		dependency.Score, config.CategoryWeights.SCA,
		trivy.Score, config.CategoryWeights.Container,
		mdsri,
	)

	details := models.CalculationDetails{
		SASTScore:         sonar.Score,
		SCAScore:          dependency.Score,
		ContainerScore:    trivy.Score,
		SASTWeighted:      sastWeighted,
		SCAWeighted:       scaWeighted,
		ContainerWeighted: containerWeighted,
		Formula:           formula,
	}

	return mdsri, details
}
