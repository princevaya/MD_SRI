package utils

import (
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
	"mdsri-engine/internal/models"
)

// LoadConfig reads the configuration file at the given path and decodes it.
func LoadConfig(path string) (*models.Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file: %w", err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config models.Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse yaml config: %w", err)
	}

	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &config, nil
}

// validateConfig validates that configuration parameters are mathematically logical.
func validateConfig(config *models.Config) error {
	// Category weights must sum to 1.0 (with a tiny float epsilon margin)
	totalCategoryWeight := config.CategoryWeights.SAST + config.CategoryWeights.SCA + config.CategoryWeights.Container
	if totalCategoryWeight < 0.99 || totalCategoryWeight > 1.01 {
		return fmt.Errorf("category weights must sum up to exactly 1.0 (found %f)", totalCategoryWeight)
	}

	if config.SeverityWeights.Critical < 0 || config.SeverityWeights.High < 0 ||
		config.SeverityWeights.Medium < 0 || config.SeverityWeights.Low < 0 {
		return fmt.Errorf("severity weights cannot be negative")
	}

	return nil
}
