package server

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
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

// EvaluateRequest represents the old POST JSON payload fallback
type EvaluateRequest struct {
	Project     string `json:"project"`
	Build       string `json:"build"`
	Environment string `json:"environment"`
	Sonar       string `json:"sonar"`
	Dependency  string `json:"dependency"`
	Trivy       string `json:"trivy"`
}

// EvaluateAPIResponse represents the response matching the requirement specification
type EvaluateAPIResponse struct {
	Decision     string  `json:"decision"`
	OverallScore float64 `json:"overall_score"`
	Threshold    float64 `json:"threshold"`
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
	engine.AddFunc("mathAdd", func(a, b float64) float64 { return a + b })

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

	// Evaluation endpoint supporting both JSON and multipart form-data
	app.Post("/evaluate", func(c *fiber.Ctx) error {
		var project, envName, buildID string
		var sonarRep, depRep, trivyRep *models.ToolReport

		contentType := c.Get(fiber.HeaderContentType)

		if strings.HasPrefix(contentType, fiber.MIMEApplicationJSON) {
			// Fallback: Parse from JSON body containing local file paths
			var req EvaluateRequest
			if err := c.BodyParser(&req); err != nil {
				log.Error().Err(err).Msg("Failed to parse request body")
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid JSON request body"})
			}
			project = req.Project
			envName = req.Environment
			buildID = req.Build

			if req.Sonar != "" {
				var err error
				sonarRep, err = parser.ParseSonarQube(req.Sonar)
				if err != nil {
					log.Error().Err(err).Msg("Failed to parse local SonarQube file")
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": fmt.Sprintf("SonarQube file error: %v", err)})
				}
			}
			if req.Dependency != "" {
				var err error
				depRep, err = parser.ParseDependencyCheck(req.Dependency)
				if err != nil {
					log.Error().Err(err).Msg("Failed to parse local Dependency Check file")
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": fmt.Sprintf("Dependency Check file error: %v", err)})
				}
			}
			if req.Trivy != "" {
				var err error
				trivyRep, err = parser.ParseTrivy(req.Trivy)
				if err != nil {
					log.Error().Err(err).Msg("Failed to parse local Trivy file")
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": fmt.Sprintf("Trivy file error: %v", err)})
				}
			}
		} else {
			// Production pipeline: Parse multipart form uploads (curl -F)
			project = c.FormValue("project")
			envName = c.FormValue("environment")
			buildID = c.FormValue("build")

			// Parse SonarQube form upload
			sonarHeader, err := c.FormFile("sonar")
			if err == nil {
				file, err := sonarHeader.Open()
				if err != nil {
					log.Error().Err(err).Msg("Failed to open uploaded sonar report")
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": fmt.Sprintf("Failed to open sonar file: %v", err)})
				}
				defer file.Close()
				data, _ := io.ReadAll(file)
				sonarRep, err = parser.ParseSonarQubeBytes(data)
				if err != nil {
					log.Error().Err(err).Msg("SonarQube upload parse error")
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": fmt.Sprintf("SonarQube parser error: %v", err)})
				}
			}

			// Parse Dependency Check form upload
			depHeader, err := c.FormFile("dependency")
			if err == nil {
				file, err := depHeader.Open()
				if err != nil {
					log.Error().Err(err).Msg("Failed to open uploaded dependency report")
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": fmt.Sprintf("Failed to open dependency file: %v", err)})
				}
				defer file.Close()
				data, _ := io.ReadAll(file)
				depRep, err = parser.ParseDependencyCheckBytes(data)
				if err != nil {
					log.Error().Err(err).Msg("Dependency Check upload parse error")
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": fmt.Sprintf("Dependency Check parser error: %v", err)})
				}
			}

			// Parse Trivy form upload
			trivyHeader, err := c.FormFile("trivy")
			if err == nil {
				file, err := trivyHeader.Open()
				if err != nil {
					log.Error().Err(err).Msg("Failed to open uploaded trivy report")
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": fmt.Sprintf("Failed to open trivy file: %v", err)})
				}
				defer file.Close()
				data, _ := io.ReadAll(file)
				trivyRep, err = parser.ParseTrivyBytes(data)
				if err != nil {
					log.Error().Err(err).Msg("Trivy upload parse error")
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": fmt.Sprintf("Trivy parser error: %v", err)})
				}
			}
		}

		// Defaults for optional fields
		if envName == "" {
			envName = "production"
		}
		if project == "" {
			project = "IEEE Research MD-SRI Analysis"
		}

		// Setup default reports if files were not provided
		if sonarRep == nil {
			sonarRep = &models.ToolReport{ToolName: "SonarQube", Category: "SAST"}
		}
		if depRep == nil {
			depRep = &models.ToolReport{ToolName: "OWASP Dependency Check", Category: "SCA"}
		}
		if trivyRep == nil {
			trivyRep = &models.ToolReport{ToolName: "Trivy", Category: "Container"}
		}

		log.Info().
			Str("project", project).
			Str("build", buildID).
			Str("env", envName).
			Msg("Starting policy evaluation")

		// Evaluate policy
		result, err := policy.EvaluatePolicy(project, envName, sonarRep, depRep, trivyRep, cfg)
		if err != nil {
			log.Error().Err(err).Msg("Failed to evaluate policy")
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}

		// Save the build ID in result
		result.Build = buildID

		// Update latestResult store thread-safely
		resultMutex.Lock()
		latestResult = result
		resultMutex.Unlock()

		// Write output/mdsri-report.json
		if err := writeJSONReport(result); err != nil {
			log.Error().Err(err).Msg("Failed to save JSON report to output/")
		}

		// Dispatch Slack Webhook notification in background
		go utils.SendSlackNotification(cfg.SlackWebhookURL, result)

		log.Info().
			Str("decision", result.Decision).
			Float64("overall_score", result.OverallScore).
			Msg("Evaluation completed successfully")

		// Return REST API Response payload matching request specification
		resp := EvaluateAPIResponse{
			Decision:     result.Decision,
			OverallScore: result.OverallScore,
			Threshold:    result.Threshold,
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
