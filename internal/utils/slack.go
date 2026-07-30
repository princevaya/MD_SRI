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
func SendSlackNotification(webhookURL string, result *models.EvaluationResult) {
	// If slack webhook URL is empty, fall back to SLACK_WEBHOOK_URL env variable
	if webhookURL == "" {
		webhookURL = os.Getenv("SLACK_WEBHOOK_URL")
	}

	// If still empty, skip silently
	if webhookURL == "" {
		log.Debug().Msg("Slack Webhook URL is not set. Skipping notification.")
		return
	}

	// Select theme color depending on decision (PASS = Green, BLOCK = Red)
	color := "#10b981" // emerald green
	statusEmoji := "✅"
	if result.Decision == "BLOCK" {
		color = "#ef4444" // red
		statusEmoji = "❌"
	}

	titleText := fmt.Sprintf("%s MD-SRI Decision: %s for %s", statusEmoji, result.Decision, result.Project)

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
						"value": result.Project,
						"short": true,
					},
					{
						"title": "Build ID",
						"value": result.Build,
						"short": true,
					},
					{
						"title": "Environment",
						"value": result.Environment,
						"short": true,
					},
					{
						"title": "Overall MD-SRI Score",
						"value": fmt.Sprintf("%.3f", result.OverallScore),
						"short": true,
					},
					{
						"title": "Risk Threshold",
						"value": fmt.Sprintf("%.2f", result.Threshold),
						"short": true,
					},
					{
						"title": "Policy Reason",
						"value": result.Reason,
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
