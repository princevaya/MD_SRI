package server

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/html/v2"
	"github.com/rs/zerolog/log"

	"mdsri-engine/internal/models"
	"mdsri-engine/internal/parser"
	"mdsri-engine/internal/policy"
	"mdsri-engine/internal/utils"
)

var (
	latestResult *models.EvaluationResult
	resultMutex  sync.RWMutex
)

// EvaluateRequest represents the POST payload
type EvaluateRequest struct {
	Project     string `json:"project"`
	Environment string `json:"environment"`
	Sonar       string `json:"sonar"`
	Dependency  string `json:"dependency"`
	Trivy       string `json:"trivy"`
}

// EvaluateAPIResponse represents the response matching the requirement specification
type EvaluateAPIResponse struct {
	OverallScore float64 `json:"overall_score"`
	Decision     string  `json:"decision"`
	Reason       string  `json:"reason"`
}

func init() {
	// Initialize default result so dashboard displays clean message initially
	latestResult = &models.EvaluationResult{
		Project:     "IEEE Research MD-SRI Analysis",
		Environment: "production",
		Timestamp:   time.Now(),
		Decision:    "BLOCK",
		Reason:      "No evaluations executed yet. Run an evaluation via CLI or REST API first.",
	}
}

// StartServer starts the Fiber v2 REST API server
func StartServer(port int, configPath string) error {
	// Verify config loads before launching
	cfg, err := utils.LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Setup template engine from local folder templates/
	engine := html.New("./templates", ".html")

	// Custom template functions for HTML rendering calculations
	engine.AddFunc("mathMul", func(a, b float64) float64 { return a * b })
	engine.AddFunc("mathSub", func(a, b float64) float64 { return a - b })
	engine.AddFunc("mathDiv", func(a, b float64) float64 {
		if b == 0 {
			return 0
		}
		return a / b
	})
	engine.AddFunc("mathMin", func(a, b float64) float64 {
		if a < b {
			return a
		}
		return b
	})
	engine.AddFunc("mathAdd3", func(a, b, c int) int { return a + b + c })

	app := fiber.New(fiber.Config{
		Views:       engine,
		ViewsLayout: "",
	})

	// Health Check endpoint
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "healthy"})
	})

	// HTML Dashboard page serving dynamic report results
	app.Get("/dashboard", func(c *fiber.Ctx) error {
		resultMutex.RLock()
		res := latestResult
		resultMutex.RUnlock()

		return c.Render("dashboard", res)
	})

	// Evaluation webhook endpoint
	app.Post("/evaluate", func(c *fiber.Ctx) error {
		var req EvaluateRequest
		if err := c.BodyParser(&req); err != nil {
			log.Error().Err(err).Msg("Failed to parse request body")
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body"})
		}

		if req.Environment == "" {
			req.Environment = "production"
		}
		if req.Project == "" {
			req.Project = "IEEE Research MD-SRI Analysis"
		}

		log.Info().
			Str("project", req.Project).
			Str("env", req.Environment).
			Str("sonar", req.Sonar).
			Str("dependency", req.Dependency).
			Str("trivy", req.Trivy).
			Msg("Starting evaluation request")

		var sonarRep, depRep, trivyRep *models.ToolReport

		// Parse SonarQube if path provided
		if req.Sonar != "" {
			var err error
			sonarRep, err = parser.ParseSonarQube(req.Sonar)
			if err != nil {
				log.Error().Err(err).Msg("Failed to parse SonarQube report")
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": fmt.Sprintf("SonarQube parser error: %v", err)})
			}
		} else {
			sonarRep = &models.ToolReport{ToolName: "SonarQube", Category: "SAST"}
		}

		// Parse OWASP Dependency Check if path provided
		if req.Dependency != "" {
			var err error
			depRep, err = parser.ParseDependencyCheck(req.Dependency)
			if err != nil {
				log.Error().Err(err).Msg("Failed to parse Dependency Check report")
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": fmt.Sprintf("Dependency Check parser error: %v", err)})
			}
		} else {
			depRep = &models.ToolReport{ToolName: "OWASP Dependency Check", Category: "SCA"}
		}

		// Parse Trivy if path provided
		if req.Trivy != "" {
			var err error
			trivyRep, err = parser.ParseTrivy(req.Trivy)
			if err != nil {
				log.Error().Err(err).Msg("Failed to parse Trivy report")
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": fmt.Sprintf("Trivy parser error: %v", err)})
			}
		} else {
			trivyRep = &models.ToolReport{ToolName: "Trivy", Category: "Container"}
		}

		// Evaluate policy
		result, err := policy.EvaluatePolicy(req.Project, req.Environment, sonarRep, depRep, trivyRep, cfg)
		if err != nil {
			log.Error().Err(err).Msg("Failed to evaluate policy")
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}

		// Update latestResult store thread-safely
		resultMutex.Lock()
		latestResult = result
		resultMutex.Unlock()

		// Write output/mdsri-report.json
		if err := writeJSONReport(result); err != nil {
			log.Error().Err(err).Msg("Failed to save JSON report to output/")
		}

		log.Info().
			Str("decision", result.Decision).
			Float64("overall_score", result.OverallScore).
			Msg("Evaluation completed successfully")

		// Return REST API Response according to requirements
		resp := EvaluateAPIResponse{
			OverallScore: result.OverallScore,
			Decision:     result.Decision,
			Reason:       result.Reason,
		}

		return c.JSON(resp)
	})

	addr := fmt.Sprintf(":%d", port)
	log.Info().Msgf("Starting REST server on %s", addr)
	return app.Listen(addr)
}

func writeJSONReport(result *models.EvaluationResult) error {
	if err := os.MkdirAll("output", 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile("output/mdsri-report.json", data, 0644)
}

// SetLatestResult sets the latest result (useful for populating from CLI runs)
func SetLatestResult(result *models.EvaluationResult) {
	resultMutex.Lock()
	latestResult = result
	resultMutex.Unlock()
}
