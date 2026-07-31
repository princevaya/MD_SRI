package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"mdsri-engine/internal/models"
)

func TestEvaluate_HandlesSlackGracefully(t *testing.T) {
	// Start server in background on a test port
	port := 9876
	configPath := "../../configs/config.yaml" // path relative to internal/server/

	go func() {
		_ = StartServer(port, configPath)
	}()

	// Wait a moment for server to start
	time.Sleep(500 * time.Millisecond)

	// We will send a request with JSON payload
	url := "http://localhost:9876/evaluate"
	reqBody, _ := json.Marshal(map[string]string{
		"project":     "Test Graceful Slack",
		"environment": "production",
		"build":       "test-build-1",
	})

	// Make request
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		t.Fatalf("Failed to send POST request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200 OK, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	var evalResp models.EvaluationResponse
	if err := json.Unmarshal(body, &evalResp); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if evalResp.Project != "Test Graceful Slack" {
		t.Errorf("Expected project 'Test Graceful Slack', got '%s'", evalResp.Project)
	}
	if evalResp.Decision != "PASS" {
		t.Errorf("Expected decision 'PASS', got '%s'", evalResp.Decision)
	}
}
