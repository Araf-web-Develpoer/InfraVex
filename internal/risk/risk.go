package risk

import "strings"

// Engine computes scores for findings
type Engine struct {
	Scores map[string]string // Finding -> Severity (e.g. "Open RDP" -> "High")
}

// NewEngine initializes the scoring mechanism based on config
func NewEngine(configScores map[string]string) *Engine {
	// Fallback/Default map
	scores := map[string]string{
		"open_rdp":     "High",
		"exposed_db":   "Critical",
		"weak_tls":     "Medium",
		"expired_cert": "Low",
	}

	// Override with provided scores
	for k, v := range configScores {
		scores[strings.ToLower(k)] = v
	}

	return &Engine{Scores: scores}
}

// EvaluatePort returns severity based on open port and basic service heuristics
func (e *Engine) EvaluatePort(port int, service string) string {
	// Simple heuristics
	if port == 3389 {
		severity := e.Scores["open_rdp"]
		if severity == "" {
			return "High"
		}
		return severity
	}
	
	if port == 3306 || port == 5432 || port == 1433 || port == 27017 {
		severity := e.Scores["exposed_db"]
		if severity == "" {
			return "Critical"
		}
		return severity
	}

	return "Info"
}

// EvaluateCert returns severity for cert findings
func (e *Engine) EvaluateCert(expired bool) string {
	if expired {
		severity := e.Scores["expired_cert"]
		if severity == "" {
			return "Low"
		}
		return severity
	}
	return "Info"
}
