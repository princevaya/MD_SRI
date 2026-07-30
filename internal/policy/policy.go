package policy

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

	// 2. Setup initial result structure
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
	}

	// 3. Evaluate Hard Veto Rules
	criticalCount := sonar.Counts.Critical + dependency.Counts.Critical + trivy.Counts.Critical
	highCount := sonar.Counts.High + dependency.Counts.High + trivy.Counts.High

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

	// 4. Compare score against threshold
	if overallScore > envPolicy.Threshold {
		result.Decision = "BLOCK"
		result.Reason = fmt.Sprintf("Overall MD-SRI score (%.2f) exceeded %s threshold (%.2f).", overallScore, envName, envPolicy.Threshold)
	} else {
		result.Decision = "PASS"
		result.Reason = fmt.Sprintf("Overall MD-SRI score (%.2f) is within %s threshold (%.2f).", overallScore, envName, envPolicy.Threshold)
	}

	return result, nil
}
