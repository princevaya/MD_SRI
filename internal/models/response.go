package models

// EvaluationResponse represents the enhanced REST API response payload
type EvaluationResponse struct {
	Project      string         `json:"project"`
	Build        string         `json:"build"`
	Environment  string         `json:"environment"`
	Decision     string         `json:"decision"`
	OverallScore float64        `json:"overall_score"`
	Threshold    float64        `json:"threshold"`
	Reason       string         `json:"reason"`
	Metrics      MetricsSummary `json:"metrics"`
}

// MetricsSummary contains category scores and aggregate vulnerability counts
type MetricsSummary struct {
	SASTScore      float64 `json:"sast_score"`
	SCAScore       float64 `json:"sca_score"`
	ContainerScore float64 `json:"container_score"`
	Counts         Counts  `json:"counts"`
}

// Counts holds the aggregated vulnerability counts across all scanners
type Counts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}
