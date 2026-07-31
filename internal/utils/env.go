package utils

import (
	"bufio"
	"os"
	"strings"

	"github.com/rs/zerolog/log"
)

// LoadEnv reads a .env file if it exists in the current directory and sets env variables.
func LoadEnv() {
	file, err := os.Open(".env")
	if err != nil {
		log.Info().Msg(".env file not found in current directory. Skipping .env loading.")
		return
	}
	defer file.Close()

	log.Info().Msg("Loading environment variables from .env file...")
	scanner := bufio.NewScanner(file)
	loadedCount := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Strip quotes if present
		if (strings.HasPrefix(value, "\"") && strings.HasSuffix(value, "\"")) ||
			(strings.HasPrefix(value, "'") && strings.HasSuffix(value, "'")) {
			value = value[1 : len(value)-1]
		}

		if err := os.Setenv(key, value); err != nil {
			log.Error().Err(err).Msgf("Failed to set env variable %s", key)
		} else {
			loadedCount++
		}
	}
	log.Info().Msgf("Successfully loaded %d environment variables from .env", loadedCount)
}
