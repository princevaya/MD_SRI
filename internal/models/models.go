package models

import "time"

// Severity represents the vulnerability level
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
)

// Finding represents a single security finding in a generic way
type Finding struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Severity    Severity `json:"severity"`
	Component   string   `json:"component"`
	Source      string   `json:"source"` // File path or package reference
}

// SeverityCounts maps severity levels to their respective counts
type SeverityCounts struct {
	Critical int `json:"critical" yaml:"critical"`
	High     int `json:"high" yaml:"high"`
	Medium   int `json:"medium" yaml:"medium"`
	Low      int `json:"low" yaml:"low"`
}

// ToolReport represents parsed counts and raw findings for a single tool
type ToolReport struct {
	ToolName string         `json:"tool_name"`
	Category string         `json:"category"` // e.g., SAST, SCA, Container
	Counts   SeverityCounts `json:"counts"`
	Score    float64        `json:"score"`
	Findings []Finding      `json:"findings,omitempty"`
}

// Config definitions mapped directly to config.yaml
type SeverityWeights struct {
	Critical float64 `yaml:"critical"`
	High     float64 `yaml:"high"`
	Medium   float64 `yaml:"medium"`
	Low      float64 `yaml:"low"`
}

type CategoryWeights struct {
	SAST      float64 `yaml:"sast"`
	SCA       float64 `yaml:"sca"`
	Container float64 `yaml:"container"`
}

type EnvPolicy struct {
	Threshold float64 `yaml:"threshold"`
}

type VetoPolicies struct {
	VetoOnCritical bool `yaml:"veto_on_critical"`
	VetoOnHigh     bool `yaml:"veto_on_high"`
}

type Config struct {
	SeverityWeights SeverityWeights      `yaml:"severity_weights"`
	CategoryWeights CategoryWeights      `yaml:"category_weights"`
	Environments    map[string]EnvPolicy `yaml:"environments"`
	VetoPolicies    VetoPolicies         `yaml:"veto_policies"`
}

// CalculationDetails holds step-by-step scoring logs
type CalculationDetails struct {
	SASTScore         float64 `json:"sast_score"`
	SCAScore          float64 `json:"sca_score"`
	ContainerScore    float64 `json:"container_score"`
	SASTWeighted      float64 `json:"sast_weighted"`
	SCAWeighted       float64 `json:"sca_weighted"`
	ContainerWeighted float64 `json:"container_weighted"`
	Formula           string  `json:"formula"`
}

// EvaluationResult represents the final MD-SRI engine run report
type EvaluationResult struct {
	Project            string             `json:"project"`
	Environment        string             `json:"environment"`
	Timestamp          time.Time          `json:"timestamp"`
	SonarReport        ToolReport         `json:"sonar_report"`
	DependencyReport   ToolReport         `json:"dependency_report"`
	TrivyReport        ToolReport         `json:"trivy_report"`
	OverallScore       float64            `json:"overall_score"`
	Threshold          float64            `json:"threshold"`
	Decision           string             `json:"decision"` // PASS or BLOCK
	Reason             string             `json:"reason"`
	CalculationDetails CalculationDetails `json:"calculation_details"`
	VetoTriggered      bool               `json:"veto_triggered"`
}
