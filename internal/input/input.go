package input

import (
	"bufio"
	"os"
	"strings"

	"veex0x01-intel/pkg/logger"
	"veex0x01-intel/pkg/utils"
	"veex0x01-intel/pkg/validator"
)

// ProcessTargets takes a single domain or a file, and validates them
func ProcessTargets(singleDomain string, scopeFile string) []string {
	var targets []string

	if singleDomain != "" {
		if validator.IsValidDomain(singleDomain) || validator.IsValidIP(singleDomain) {
			targets = append(targets, strings.ToLower(singleDomain))
		} else {
			logger.Warn("Invalid target format, skipping", map[string]interface{}{"target": singleDomain})
		}
	}

	if scopeFile != "" && utils.FileExists(scopeFile) {
		file, err := os.Open(scopeFile)
		if err != nil {
			logger.Error("Could not open scope file", err)
			return targets
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			
			if validator.IsValidDomain(line) || validator.IsValidIP(line) || validator.IsValidCIDR(line) {
				targets = append(targets, strings.ToLower(line))
			} else {
				logger.Warn("Invalid line in scope file", map[string]interface{}{"line": line})
			}
		}

		if err := scanner.Err(); err != nil {
			logger.Error("Issue reading scope file", err)
		}
	}

	return targets
}
