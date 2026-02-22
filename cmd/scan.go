package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"InfraVex/internal/input"
	"InfraVex/internal/network"
	"InfraVex/internal/reporting"
	"InfraVex/internal/resolver"
	"InfraVex/internal/scanner"
	"InfraVex/internal/scope"
	"InfraVex/internal/storage"
	"InfraVex/pkg/logger"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	domain    string
	scopeFile string
	mode      string
)

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Start an intelligence gathering scan",
	Long:  `Initiate a scan against a specific domain or scope file.`,
	Run: func(cmd *cobra.Command, args []string) {
		logger.Info("Starting InfraVex scan sequence", map[string]interface{}{
			"mode":   mode,
			"target": domain,
		})

		if mode == "active" {
			confirmActiveMode()
		}

		// Setup Context and Graceful Shutdown
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-c
			logger.Warn("Shutdown signal received, aborting gracefully...", nil)
			cancel()
		}()

		runScan(ctx)
		
		logger.Info("Scan sequence complete.", nil)
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().StringVarP(&domain, "domain", "D", "", "Target domain (e.g., example.com)")
	scanCmd.Flags().StringVarP(&scopeFile, "scope", "S", "", "Path to scope configuration file")
	scanCmd.Flags().StringVarP(&mode, "mode", "M", "passive", "Scan mode: passive or active")
	
}

func confirmActiveMode() {
	fmt.Println("==================================================")
	fmt.Println("⚠️  WARNING: ACTIVE MODE INITIATED")
	fmt.Println("Active mode performs intrusive actions like port scanning and service fingerprinting.")
	fmt.Println("Ensure you have explicit authorization before proceeding.")
	fmt.Print("Type 'YES' to confirm: ")

	var response string
	fmt.Scanln(&response)

	if response != "YES" {
		logger.Fatal("Active mode confirmation rejected. Exiting.", nil)
	}
}

// runScan orchestrates the actual scanning workflow
func runScan(ctx context.Context) {
	// 1. Process Input
	targets := input.ProcessTargets(domain, scopeFile)
	if len(targets) == 0 {
		logger.Warn("No valid targets provided. Exiting.", nil)
		return
	}
	
	logger.Info("Initializing scope engine", map[string]interface{}{"targets_count": len(targets)})
	scopeEngine := scope.NewEngine(targets)

	// 2. Initialize Storage
	db, err := storage.InitSQLite("infravex.db")
	if err != nil {
		logger.Error("Failed to initialize database", err)
	} else {
		defer db.Close()
	}

	var reportAssets []storage.Asset

	// 3. Network Resolution & Scanning
	logger.Info("Running network resolution module...", nil)
	for _, t := range targets {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if !scopeEngine.IsInScope(t) {
			continue
		}

		rec, err := resolver.Resolve(ctx, t)
		if err != nil {
			continue
		}

		for _, ip := range rec.IPs {
			asset := storage.Asset{
				IP:         ip,
				Hostname:   rec.Domain,
				Source:     "DNS",
				Discovered: time.Now(),
			}

			// Add WHOIS/ASN Intelligence
			logger.Info("Querying network intelligence", map[string]interface{}{"ip": ip})
			ipInfo, err := network.GetInfo(ip)
			
			isCDN := false
			if err == nil && ipInfo != nil {
				asset.Source = fmt.Sprintf("ASN: %s (%s)", ipInfo.ASN, ipInfo.Org)
				
				// Auto-Detect CDN Edge Nodes to prevent useless edge scanning
				orgLower := strings.ToLower(ipInfo.Org)
				if strings.Contains(orgLower, "cloudflare") || 
				   strings.Contains(orgLower, "akamai") ||
				   strings.Contains(orgLower, "fastly") ||
				   strings.Contains(orgLower, "amazon") {
					isCDN = true
				}
			}

			if mode == "active" {
				if isCDN {
					logger.Warn("IP belongs to CDN edge. Skipping active port scan.", map[string]interface{}{
						"ip": ip,
						"cdn": ipInfo.Org,
					})
				} else {
					logger.Info("Running active scanner...", map[string]interface{}{"ip": ip})
					
					ports := viper.GetIntSlice("scanning.top_ports")
				if len(ports) == 0 {
					ports = []int{80, 443}
				}
				
				maxWorkers := viper.GetInt("performance.max_workers")
				if maxWorkers == 0 {
					maxWorkers = 50
				}
				
				timeout := viper.GetInt("performance.timeout_seconds")
				if timeout == 0 {
					timeout = 5
				}

				s := scanner.NewActiveScan(ports, timeout, maxWorkers)
				openPorts := s.ScanTargets(ctx, ip)
				
				var strPorts []string
				for _, p := range openPorts {
					strPorts = append(strPorts, fmt.Sprintf("%d", p))
				}
				asset.Ports = strings.Join(strPorts, ",")
				}
			}

			if db != nil {
				db.SaveAsset(&asset)
			}
			reportAssets = append(reportAssets, asset)
		}
	}

	// 4. Generate Reporting
	logger.Info("Generating risk report...", nil)
	rep := &reporting.Report{
		ProjectName: "InfraVex",
		ScanTime:    time.Now(),
		Author:      "medjahdi",
		Summary: map[string]int{
			"total_targets": len(targets),
			"total_assets":  len(reportAssets),
		},
		Assets: reportAssets,
	}

	reporting.GenerateJSON("report.json", rep)
	reporting.GenerateMarkdown("report.md", rep)
	reporting.PrintTable(rep)
}
