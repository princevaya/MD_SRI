package utils

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"mdsri-engine/internal/models"
)

func TestSendSlackNotification_EmptyURL(t *testing.T) {
	t.Setenv("SLACK_WEBHOOK_URL", "")
	resp := models.EvaluationResponse{
		Project:      "TestProj",
		Build:        "123",
		Environment:  "production",
		Decision:     "PASS",
		OverallScore: 5.5,
		Threshold:    8.0,
		Reason:       "All good",
		Metrics: models.MetricsSummary{
			SASTScore: 2.0,
			SCAScore:  1.5,
			Counts: models.Counts{
				Critical: 0,
				High:     1,
			},
		},
	}

	// This should not panic or hang
	SendSlackNotification("", resp)
}

func TestSendSlackNotification_InvalidURL(t *testing.T) {
	t.Setenv("SLACK_WEBHOOK_URL", "")
	resp := models.EvaluationResponse{
		Project:      "TestProj",
		Build:        "123",
		Environment:  "production",
		Decision:     "BLOCK",
		OverallScore: 12.5,
		Threshold:    8.0,
		Reason:       "Too risky",
		Metrics: models.MetricsSummary{
			SASTScore: 5.0,
			SCAScore:  5.0,
			Counts: models.Counts{
				Critical: 1,
				High:     2,
			},
		},
	}

	// This should return immediately / fail gracefully without crashing/panicking
	SendSlackNotification("http://127.0.0.1:9999/invalid-endpoint-that-doesnt-exist", resp)
}

func TestSendSlackNotification_Success(t *testing.T) {
	t.Setenv("SLACK_WEBHOOK_URL", "")
	// Create a test HTTP server to mock Slack webhook
	var receivedPayload map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		decoder := json.NewDecoder(req.Body)
		if err := decoder.Decode(&receivedPayload); err != nil {
			t.Errorf("Failed to decode payload: %v", err)
		}
	}))
	defer server.Close()

	resp := models.EvaluationResponse{
		Project:      "TestProj",
		Build:        "123",
		Environment:  "production",
		Decision:     "PASS",
		OverallScore: 5.5,
		Threshold:    8.0,
		Reason:       "All good",
		Metrics: models.MetricsSummary{
			SASTScore: 2.0,
			SCAScore:  1.5,
			Counts: models.Counts{
				Critical: 0,
				High:     1,
			},
		},
	}

	SendSlackNotification(server.URL, resp)

	if receivedPayload == nil {
		t.Fatal("Mock server did not receive payload")
	}

	attachments, ok := receivedPayload["attachments"].([]interface{})
	if !ok || len(attachments) == 0 {
		t.Fatal("Payload missing attachments")
	}

	attachment, ok := attachments[0].(map[string]interface{})
	if !ok {
		t.Fatal("Attachment is not a map")
	}

	color, _ := attachment["color"].(string)
	if color != "#36a64f" {
		t.Errorf("Expected PASS color #36a64f, got %s", color)
	}

	fields, ok := attachment["fields"].([]interface{})
	if !ok || len(fields) < 5 {
		t.Fatalf("Expected at least 5 fields in attachment, got %v", len(fields))
	}

	// Verify project matches
	projectFound := false
	for _, fieldVal := range fields {
		fMap, ok := fieldVal.(map[string]interface{})
		if !ok {
			continue
		}
		if fMap["title"] == "Project" && fMap["value"] == "TestProj" {
			projectFound = true
		}
	}
	if !projectFound {
		t.Error("Project 'TestProj' not found in Slack payload fields")
	}
}

func TestSendSlackNotification_BlockColor(t *testing.T) {
	t.Setenv("SLACK_WEBHOOK_URL", "")
	var receivedColor string
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		var payload map[string]interface{}
		decoder := json.NewDecoder(req.Body)
		_ = decoder.Decode(&payload)
		if attachments, ok := payload["attachments"].([]interface{}); ok && len(attachments) > 0 {
			if attachment, ok := attachments[0].(map[string]interface{}); ok {
				receivedColor, _ = attachment["color"].(string)
			}
		}
	}))
	defer server.Close()

	resp := models.EvaluationResponse{
		Project:     "TestProj",
		Decision:    "BLOCK",
		Metrics:     models.MetricsSummary{},
	}

	SendSlackNotification(server.URL, resp)

	if receivedColor != "#FF0000" {
		t.Errorf("Expected BLOCK color #FF0000, got %s", receivedColor)
	}
}

func TestSendSlackNotification_PanicRecovery(t *testing.T) {
	t.Setenv("SLACK_WEBHOOK_URL", "")
	SendSlackNotification(":", models.EvaluationResponse{})
}
