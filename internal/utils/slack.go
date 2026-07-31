package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/rs/zerolog/log"
	"mdsri-engine/internal/models"
)

// SendSlackNotification sends a formatted Slack webhook message using standard Attachments.
func SendSlackNotification(webhookURL string, res models.EvaluationResponse) {
	// Wrap in a defer recover block to catch panics and prevent crashing the server
	defer func() {
		if r := recover(); r != nil {
			log.Error().Interface("panic", r).Msg("Recovered from panic in SendSlackNotification")
		}
	}()

	// Environment variable SLACK_WEBHOOK_URL takes precedence and overrides config settings
	if envWebhook := os.Getenv("SLACK_WEBHOOK_URL"); envWebhook != "" {
		webhookURL = envWebhook
	}

	// If still empty, skip silently
	if webhookURL == "" {
		log.Debug().Msg("Slack Webhook URL is not set. Skipping notification.")
		return
	}

	// Select theme color depending on decision (PASS = #36a64f, BLOCK = #FF0000)
	color := "#36a64f"
	statusEmoji := "✅"
	if res.Decision == "BLOCK" {
		color = "#FF0000"
		statusEmoji = "❌"
	}

	titleText := fmt.Sprintf("%s MD-SRI Decision: %s for %s", statusEmoji, res.Decision, res.Project)

	// Build Slack payload structure with fields
	payload := map[string]interface{}{
		"attachments": []map[string]interface{}{
			{
				"color":    color,
				"fallback": titleText,
				"pretext":  "📢 *MD-SRI Policy Evaluation Triggered*",
				"title":    titleText,
				"fields": []map[string]interface{}{
					{
						"title": "Project",
						"value": res.Project,
						"short": true,
					},
					{
						"title": "Build ID",
						"value": res.Build,
						"short": true,
					},
					{
						"title": "Environment",
						"value": res.Environment,
						"short": true,
					},
					{
						"title": "Overall Risk Score vs. Threshold",
						"value": fmt.Sprintf("%.3f / %.2f", res.OverallScore, res.Threshold),
						"short": true,
					},
					{
						"title": "Policy Reason",
						"value": res.Reason,
						"short": false,
					},
					{
						"title": "Score Breakdown",
						"value": fmt.Sprintf("  ↳ SAST (SonarQube): %.2f\n  ↳ SCA (Dependency-Check): %.2f\n  ↳ Container (Trivy): %.2f", res.Metrics.SASTScore, res.Metrics.SCAScore, res.Metrics.ContainerScore),
						"short": false,
					},
					{
						"title": "Severity Breakdown",
						"value": fmt.Sprintf("🔴 %d Critical | 🟠 %d High | 🟡 %d Medium | ⚪ %d Low", res.Metrics.Counts.Critical, res.Metrics.Counts.High, res.Metrics.Counts.Medium, res.Metrics.Counts.Low),
						"short": false,
					},
				},
				"footer": "MD-SRI Risk Engine - IEEE DevSecOps Research",
				"ts":     time.Now().Unix(),
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal Slack message payload")
		return
	}

	// Perform HTTP POST to the webhook URL
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(webhookURL, "application/json", bytes.NewBuffer(body))
	if err != nil {
		log.Error().Err(err).Msg("Failed to send Slack webhook POST")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		log.Error().Msgf("Slack webhook returned non-OK status: %d", resp.StatusCode)
		return
	}

	log.Info().Msg("Slack notification dispatched successfully")
}
