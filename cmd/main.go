package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"mdsri-engine/internal/models"
	"mdsri-engine/internal/parser"
	"mdsri-engine/internal/policy"
	"mdsri-engine/internal/server"
	"mdsri-engine/internal/utils"
)

func main() {
	// Configure zerolog for pretty console layout on standard error
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	subcommand := os.Args[1]
	switch subcommand {
	case "server":
		serverCmd := flag.NewFlagSet("server", flag.ExitOnError)
		port := serverCmd.Int("port", 8080, "Port for the REST API server")
		configPath := serverCmd.String("config", "configs/config.yaml", "Path to config file")
		_ = serverCmd.Parse(os.Args[2:])

		log.Info().Msgf("Starting MD-SRI Engine REST API Server on port %d...", *port)
		if err := server.StartServer(*port, *configPath); err != nil {
			log.Fatal().Err(err).Msg("Server exited with error")
		}

	case "evaluate":
		evalCmd := flag.NewFlagSet("evaluate", flag.ExitOnError)
		env := evalCmd.String("env", "production", "Target environment (development, testing, staging, production)")
		sonar := evalCmd.String("sonar", "", "Path to SonarQube JSON report")
		dependency := evalCmd.String("dependency", "", "Path to OWASP Dependency Check JSON report")
		trivy := evalCmd.String("trivy", "", "Path to Trivy JSON report")
		configPath := evalCmd.String("config", "configs/config.yaml", "Path to config file")
		project := evalCmd.String("project", "IEEE Research MD-SRI Analysis", "Project name")
		_ = evalCmd.Parse(os.Args[2:])

		log.Info().Msg("Starting CLI policy evaluation...")

		// Load config
		cfg, err := utils.LoadConfig(*configPath)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to load configuration")
		}

		// Parse reports
		var sonarRep, depRep, trivyRep *models.ToolReport

		if *sonar != "" {
			sonarRep, err = parser.ParseSonarQube(*sonar)
			if err != nil {
				log.Fatal().Err(err).Msg("Failed to parse SonarQube report")
			}
		} else {
			sonarRep = &models.ToolReport{ToolName: "SonarQube", Category: "SAST"}
		}

		if *dependency != "" {
			depRep, err = parser.ParseDependencyCheck(*dependency)
			if err != nil {
				log.Fatal().Err(err).Msg("Failed to parse Dependency Check report")
			}
		} else {
			depRep = &models.ToolReport{ToolName: "OWASP Dependency Check", Category: "SCA"}
		}

		if *trivy != "" {
			trivyRep, err = parser.ParseTrivy(*trivy)
			if err != nil {
				log.Fatal().Err(err).Msg("Failed to parse Trivy report")
			}
		} else {
			trivyRep = &models.ToolReport{ToolName: "Trivy", Category: "Container"}
		}

		// Evaluate policy
		result, err := policy.EvaluatePolicy(*project, *env, sonarRep, depRep, trivyRep, cfg)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to evaluate policy")
		}

		// Update server latest result in case server is run programmatically
		server.SetLatestResult(result)

		// Write to output/mdsri-report.json
		if err := os.MkdirAll("output", 0755); err != nil {
			log.Error().Err(err).Msg("Failed to create output directory")
		} else {
			data, _ := json.MarshalIndent(result, "", "  ")
			if err := os.WriteFile("output/mdsri-report.json", data, 0644); err != nil {
				log.Error().Err(err).Msg("Failed to save JSON report")
			} else {
				log.Info().Msg("Saved JSON report to output/mdsri-report.json")
			}
		}

		// Print summary to console
		log.Info().
			Str("Project", result.Project).
			Str("Environment", result.Environment).
			Float64("Overall Score", result.OverallScore).
			Float64("Threshold", result.Threshold).
			Str("Decision", result.Decision).
			Str("Reason", result.Reason).
			Msg("Policy Evaluation Complete")

		// Jenkins Integration: exit 0 on PASS, 1 on BLOCK
		if result.Decision == "PASS" {
			os.Exit(0)
		} else {
			os.Exit(1)
		}

	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("MD-SRI Security Risk Index Engine")
	fmt.Println("Usage:")
	fmt.Println("  go run cmd/main.go [server|evaluate] [options]")
	fmt.Println()
	fmt.Println("Subcommands:")
	fmt.Println("  server")
	fmt.Println("    Start REST API server and HTML Dashboard")
	fmt.Println("    Options:")
	fmt.Println("      --port <int>         (default: 8080)")
	fmt.Println("      --config <path>      (default: configs/config.yaml)")
	fmt.Println()
	fmt.Println("  evaluate")
	fmt.Println("    Evaluate security reports and output a decision")
	fmt.Println("    Options:")
	fmt.Println("      --env <env>          (default: production)")
	fmt.Println("      --sonar <path>       SonarQube report (JSON)")
	fmt.Println("      --dependency <path>  OWASP Dependency Check report (JSON)")
	fmt.Println("      --trivy <path>       Trivy report (JSON)")
	fmt.Println("      --config <path>      (default: configs/config.yaml)")
	fmt.Println("      --project <name>     (default: IEEE Research MD-SRI Analysis)")
}
