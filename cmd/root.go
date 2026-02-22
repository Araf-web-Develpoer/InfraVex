package cmd

import (
	"fmt"
	"os"

	"veex0x01-intel/pkg/logger"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string
var debug bool

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "veex0x01-intel",
	Short: "Infrastructure Intelligence & Attack Surface Mapping Framework",
	Long: `veex0x01-intel is strictly for authorized security assessments,
Blue/Purple team operations, internal visibility, and bug bounty within scope.
Built by: veex0x01`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Initialize Config & Logger before any command runs
		initConfig()
		logger.InitConfig(debug)
	},
	Run: func(cmd *cobra.Command, args []string) {
		// Show the banner and default help if no command is specified
		printBanner()
		cmd.Help()
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main().
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "config.yaml", "config file (default is config.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "Enable debug level logging")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.AddConfigPath(".")
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		fmt.Println("Warning: Can't read config:", err)
	}
}

func printBanner() {
	banner := `
  _    _  ___  ___ __  __ ___  ___ ___  ___  __    _  _ _ _____ ___ _    
 \ \  / /| __|| __|\ \/ // _ \|_  / _ \|_  | \ \  / /| | |_   _| __| |   
  \ \/ / | _| | _|  >  <| (_) |/ / (_) |/ /   \ \/ / | |   | | | _|| |__ 
   \__/  |___||___|/_/\_\\___//___\___//___|   \__/  |_|   |_| |___|____|
                                                                        
 Infrastructure Intelligence Engine | Built by veex0x01
 ----------------------------------------------------
 WARNING: For Authorized Assessments ONLY.
 ----------------------------------------------------
`
	fmt.Println(banner)
}
