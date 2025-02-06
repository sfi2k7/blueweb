package airouter

import (
	"fmt"
	"regexp"
	"strings"
)

// parseParam parses a parameter pattern and returns a ParamDefinition
func parseParam(pattern string) (*ParamDefinition, error) {
	// Remove curly braces
	pattern = strings.Trim(pattern, "{}")

	parts := strings.Split(pattern, ":")
	param := &ParamDefinition{
		Name: parts[0],
	}

	// Check if parameter is optional
	if strings.HasSuffix(param.Name, "?") {
		param.Name = strings.TrimSuffix(param.Name, "?")
		param.IsOptional = true
	}

	if len(parts) > 1 {
		// Get regex pattern
		regexPattern := parts[1]

		// Handle default value if present
		if len(parts) > 2 {
			param.DefaultValue = parts[2]
		}

		// Handle special patterns
		switch regexPattern {
		case "num":
			regexPattern = `\d+`
		case "alpha":
			regexPattern = `[a-zA-Z]+`
		case "alphanum":
			regexPattern = `[a-zA-Z0-9]+`
		}

		// Compile regex
		regex, err := regexp.Compile("^" + regexPattern + "$")
		if err != nil {
			return nil, fmt.Errorf("invalid regex pattern: %v", err)
		}
		param.Regex = regex
	}

	return param, nil
}
