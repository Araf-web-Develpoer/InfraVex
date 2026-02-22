package cmd

import (
	"fmt"
	"os"

	"InfraVex/pkg/logger"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string
var debug bool

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "InfraVex",
	Short: "InfraVex - Infrastructure mapping framework",
	Long: `InfraVex is strictly for authorized security assessments,
blue/purple team operations, and internal visibility.
Built by: medjahdi`,
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
    ____       _                 
   /  _/____  / __/________ _    _____  _  __
   / // __ \/ /_/ ___/ __ \ | / / _ \| |/_/
 _/ // / / / __/ /  / /_/ / |/ /  __/>  <  
/___/_/ /_/_/ /_/   \__,_/|___/\___/_/|_|  

 Infrastructure Intelligence Engine | Built by medjahdi
 ----------------------------------------------------
 WARNING: For Authorized Assessments ONLY.
 ----------------------------------------------------
`
	fmt.Println(banner)
}
