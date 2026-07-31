package evaluator

import (
	"fmt"
	"strings"
	"time"

	"mdsri-engine/internal/calculator"
	"mdsri-engine/internal/models"
)

// EvaluatePolicy evaluates the parsed reports against the config policies and environment thresholds.
func EvaluatePolicy(
	project string,
	envName string,
	sonar *models.ToolReport,
	dependency *models.ToolReport,
	trivy *models.ToolReport,
	config *models.Config,
) (*models.EvaluationResult, error) {
	// Standardize environment name to lowercase
	envKey := strings.ToLower(envName)
	envPolicy, exists := config.Environments[envKey]
	if !exists {
		return nil, fmt.Errorf("environment '%s' is not defined in configuration", envName)
	}

	// 1. Calculate scores
	overallScore, calcDetails := calculator.CalculateMDSRI(sonar, dependency, trivy, config)

	// 2. Aggregate vulnerability counts
	criticalCount := sonar.Counts.Critical + dependency.Counts.Critical + trivy.Counts.Critical
	highCount := sonar.Counts.High + dependency.Counts.High + trivy.Counts.High
	mediumCount := sonar.Counts.Medium + dependency.Counts.Medium + trivy.Counts.Medium
	lowCount := sonar.Counts.Low + dependency.Counts.Low + trivy.Counts.Low

	// 3. Setup result structure with MetricsSummary
	result := &models.EvaluationResult{
		Project:            project,
		Environment:        envName,
		Timestamp:          time.Now(),
		SonarReport:        *sonar,
		DependencyReport:   *dependency,
		TrivyReport:        *trivy,
		OverallScore:       overallScore,
		Threshold:          envPolicy.Threshold,
		CalculationDetails: calcDetails,
		Metrics: models.MetricsSummary{
			SASTScore:      calcDetails.SASTScore,
			SCAScore:       calcDetails.SCAScore,
			ContainerScore: calcDetails.ContainerScore,
			Counts: models.Counts{
				Critical: criticalCount,
				High:     highCount,
				Medium:   mediumCount,
				Low:      lowCount,
			},
		},
	}

	// 4. Evaluate Hard Veto Rules
	if config.VetoPolicies.VetoOnCritical && criticalCount > 0 {
		result.Decision = "BLOCK"
		result.Reason = fmt.Sprintf("Hard veto triggered: %d Critical vulnerability/vulnerabilities found.", criticalCount)
		result.VetoTriggered = true
		return result, nil
	}

	if config.VetoPolicies.VetoOnHigh && highCount > 0 {
		result.Decision = "BLOCK"
		result.Reason = fmt.Sprintf("Hard veto triggered: %d High vulnerability/vulnerabilities found.", highCount)
		result.VetoTriggered = true
		return result, nil
	}

	// 5. Compare score against threshold
	if overallScore > envPolicy.Threshold {
		result.Decision = "BLOCK"
		result.Reason = fmt.Sprintf("Overall MD-SRI score (%.2f) exceeded %s threshold (%.2f).", overallScore, envName, envPolicy.Threshold)
	} else {
		result.Decision = "PASS"
		result.Reason = fmt.Sprintf("Overall MD-SRI score (%.2f) is within %s threshold (%.2f).", overallScore, envName, envPolicy.Threshold)
	}

	return result, nil
}
