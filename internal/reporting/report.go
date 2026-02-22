package reporting

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"veex0x01-intel/internal/storage"
	"veex0x01-intel/pkg/logger"
)

// Report structure captures the final output
type Report struct {
	ProjectName string          `json:"project"`
	ScanTime    time.Time       `json:"scan_time"`
	Author      string          `json:"author"`
	Summary     map[string]int  `json:"summary"` // e.g. "total_ips": 500
	Assets      []storage.Asset `json:"assets"`
}

// GenerateJSON dumps the report object to a file
func GenerateJSON(filename string, rep *Report) error {
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}

	err = os.WriteFile(filename, data, 0644)
	if err == nil {
		logger.Info("JSON Report generated successfully", map[string]interface{}{"file": filename})
	}
	return err
}

// GenerateMarkdown exports a human-readable markdown file
func GenerateMarkdown(filename string, rep *Report) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	file.WriteString(fmt.Sprintf("# Infrastructure Intelligence Report\n\n"))
	file.WriteString(fmt.Sprintf("**Project:** %s\n", rep.ProjectName))
	file.WriteString(fmt.Sprintf("**Date:** %s\n", rep.ScanTime.Format(time.RFC3339)))
	file.WriteString(fmt.Sprintf("**Author:** %s\n\n", rep.Author))

	file.WriteString("## Final Summary\n\n")
	file.WriteString(fmt.Sprintf("- Total IPs discovered: %d\n", rep.Summary["total_assets"]))
	file.WriteString(fmt.Sprintf("- Total Domains found: %d\n\n", rep.Summary["total_targets"]))

	// Would loop through assets and dump findings here
	file.WriteString("## Assets\n\n")
	file.WriteString("| IP | Hostname | Open Ports | Context (ASN/Source) |\n")
	file.WriteString("|----|----------|------------|----------------------|\n")
	for _, asset := range rep.Assets {
		file.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n", asset.IP, asset.Hostname, asset.Ports, asset.Source))
	}

	logger.Info("Markdown Report generated successfully", map[string]interface{}{"file": filename})
	return nil
}

// PrintTable displays the final findings compactly to the CLI window
func PrintTable(rep *Report) {
	fmt.Println("\n========================= Scan Summary =========================")
	fmt.Printf("%-20s %-30s %-15s %-30s\n", "IP ADDRESS", "HOSTNAME", "PORTS", "CONTEXT")
	fmt.Println("--------------------------------------------------------------------------------")
	if len(rep.Assets) == 0 {
		fmt.Printf("%-20s %-30s %-15s %-30s\n", "No assets found.", "", "", "")
	} else {
		for _, asset := range rep.Assets {
			fmt.Printf("%-20s %-30s %-15s %-30s\n", asset.IP, asset.Hostname, asset.Ports, asset.Source)
		}
	}
	fmt.Println("================================================================================")
}
