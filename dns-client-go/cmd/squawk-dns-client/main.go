package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/penguincloud/squawk/dns-client-go/pkg/client"
	"github.com/penguincloud/squawk/dns-client-go/pkg/config"
	"github.com/penguincloud/squawk/dns-client-go/pkg/forwarder"
	"github.com/penguincloud/squawk/dns-client-go/pkg/license"
	"github.com/spf13/cobra"
)

var (
	// Global flags
	configFile  string
	domain      string
	recordType  string
	serverURL   string
	authToken   string
	clientCert  string
	clientKey   string
	caCert      string
	verifySSL   bool
	udpForward  bool
	tcpForward  bool
	verbose     bool
	jsonOutput  bool

	// Version information
	version   = "1.0.0"
	buildTime = "unknown"
	gitCommit = "unknown"
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "squawk-dns-client",
	Short: "Squawk DNS-over-HTTPS Client",
	Long: `A DNS-over-HTTPS client with mTLS support and local DNS forwarding capabilities.
Compatible with the Squawk DNS server and supports bearer token authentication.`,
	Version: fmt.Sprintf("%s (built %s, commit %s)", version, buildTime, gitCommit),
	Run:     runClient,
}

func init() {
	// Global flags
	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "", "Configuration file path")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	
	// DNS query flags
	rootCmd.Flags().StringVarP(&domain, "domain", "d", "", "Domain to query (required)")
	rootCmd.Flags().StringVarP(&recordType, "type", "t", "A", "DNS record type")
	rootCmd.Flags().BoolVarP(&jsonOutput, "json", "j", false, "Output in JSON format")
	
	// Server connection flags
	rootCmd.Flags().StringVarP(&serverURL, "server", "s", "", "DNS server URL")
	rootCmd.Flags().StringVarP(&authToken, "auth", "a", "", "Authentication token")
	
	// mTLS flags
	rootCmd.Flags().StringVar(&clientCert, "client-cert", "", "Client certificate file for mTLS")
	rootCmd.Flags().StringVar(&clientKey, "client-key", "", "Client private key file for mTLS")
	rootCmd.Flags().StringVar(&caCert, "ca-cert", "", "CA certificate file for server verification")
	rootCmd.Flags().BoolVar(&verifySSL, "verify-ssl", true, "Verify SSL/TLS certificates")
	
	// DNS forwarding flags
	rootCmd.Flags().BoolVarP(&udpForward, "udp", "u", false, "Enable UDP DNS forwarding on port 53")
	rootCmd.Flags().BoolVarP(&tcpForward, "tcp", "T", false, "Enable TCP DNS forwarding on port 53")

	// Add subcommands
	rootCmd.AddCommand(forwardCmd)
	rootCmd.AddCommand(configCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(licenseCmd)
}

// runClient is the main client function
func runClient(cmd *cobra.Command, args []string) {
	// Load configuration
	cfg, err := loadConfiguration()
	if err != nil {
		log.Fatalf("Configuration error: %v", err)
	}

	// Override config with command line flags
	overrideConfigWithFlags(cmd, cfg)

	if verbose {
		fmt.Println(cfg.String())
	}

	// Check if license is configured - skip validation if not (backward compatibility)
	if cfg.License.LicenseKey != "" || cfg.License.UserToken != "" {
		// Validate license before proceeding
		validator := license.NewValidator(cfg.License)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		isValid, err := validator.IsValid(ctx)
		if err != nil {
			if verbose {
				fmt.Printf("License validation warning: %v\n", err)
			}
			// Allow offline operation for now, but warn user
			fmt.Println("Warning: Could not validate license. Some features may be restricted.")
		} else if !isValid {
			fmt.Println("ERROR: Invalid or expired license. Please check your license key or user token.")
			fmt.Println("Contact your administrator for license assistance.")
			os.Exit(1)
		} else if verbose {
			fmt.Println("✓ License validated successfully")
			if info, err := validator.GetLicenseInfo(ctx); err == nil {
				fmt.Println(info)
			}
		}
	} else if verbose {
		fmt.Println("Note: No license configured. Running in compatibility mode.")
		fmt.Println("For premium features, configure SQUAWK_LICENSE_KEY or SQUAWK_USER_TOKEN.")
	}

	// Use license user token for DNS requests if available and no explicit auth token set
	if cfg.License.UserToken != "" && cfg.Client.AuthToken == "" {
		cfg.Client.AuthToken = cfg.License.UserToken
		if verbose {
			fmt.Println("Using license user token for DNS authentication")
		}
	}

	// Validate domain is provided
	if cfg.Domain == "" {
		fmt.Fprintf(os.Stderr, "Error: domain is required. Use -d <domain> or set SQUAWK_DOMAIN environment variable.\n")
		os.Exit(1)
	}

	// Create DoH client
	dohClient, err := client.NewDoHClient(cfg.Client)
	if err != nil {
		log.Fatalf("Failed to create DoH client: %v", err)
	}
	defer func() {
		if err := dohClient.Close(); err != nil {
			log.Printf("Warning: failed to close DoH client: %v", err)
		}
	}()

	// If forwarding is enabled, start forwarder and wait
	if cfg.Forwarder.ListenUDP || cfg.Forwarder.ListenTCP {
		runForwarder(dohClient, cfg)
		return
	}

	// Perform single DNS query
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	response, err := dohClient.Query(ctx, cfg.Domain, cfg.RecordType)
	if err != nil {
		log.Fatalf("DNS query failed: %v", err)
	}

	// Output results
	if jsonOutput {
		jsonData, _ := json.MarshalIndent(response, "", "  ")
		fmt.Println(string(jsonData))
	} else {
		printDNSResponse(response)
	}
}

// loadConfiguration loads the configuration from file and environment
func loadConfiguration() (*config.AppConfig, error) {
	return config.LoadConfig(configFile)
}

// overrideConfigWithFlags overrides configuration with command line flags
func overrideConfigWithFlags(cmd *cobra.Command, cfg *config.AppConfig) {
	if domain != "" {
		cfg.Domain = domain
	}
	if recordType != "" {
		cfg.RecordType = recordType
	}
	if serverURL != "" {
		cfg.Client.ServerURL = serverURL
	}
	if authToken != "" {
		cfg.Client.AuthToken = authToken
	}
	if clientCert != "" {
		cfg.Client.ClientCert = clientCert
	}
	if clientKey != "" {
		cfg.Client.ClientKey = clientKey
	}
	if caCert != "" {
		cfg.Client.CaCert = caCert
	}
	if cmd.Flags().Changed("verify-ssl") {
		cfg.Client.VerifySSL = verifySSL
	}
	if udpForward {
		cfg.Forwarder.ListenUDP = true
	}
	if tcpForward {
		cfg.Forwarder.ListenTCP = true
	}
}

// runForwarder starts the DNS forwarder service
func runForwarder(dohClient *client.DoHClient, cfg *config.AppConfig) {
	fwd := forwarder.NewForwarder(dohClient, cfg.Forwarder)

	// Handle graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start forwarder in goroutine
	go func() {
		if err := fwd.Start(ctx); err != nil {
			log.Printf("Forwarder error: %v", err)
		}
	}()

	// Wait for shutdown signal
	<-sigChan
	log.Println("Received shutdown signal, stopping forwarder...")
	cancel()

	// Give some time for graceful shutdown
	time.Sleep(1 * time.Second)
}

// printDNSResponse prints the DNS response in a human-readable format
func printDNSResponse(response *client.DNSResponse) {
	fmt.Printf("DNS Response Status: %d\n", response.Status)
	
	if response.Comment != "" {
		fmt.Printf("Comment: %s\n", response.Comment)
	}

	if len(response.Answer) > 0 {
		fmt.Println("Answers:")
		for _, answer := range response.Answer {
			fmt.Printf("  %s -> %s (TTL: %d)\n", answer.Name, answer.Data, answer.TTL)
		}
	} else {
		fmt.Println("No answers found")
	}
}

// Forward command
var forwardCmd = &cobra.Command{
	Use:   "forward",
	Short: "Start DNS forwarding service",
	Long: `Start the DNS forwarding service to forward traditional DNS queries to DNS-over-HTTPS.
This will listen on the configured UDP and/or TCP addresses and forward all DNS queries
to the configured DoH server.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Load configuration
		cfg, err := loadConfiguration()
		if err != nil {
			log.Fatalf("Configuration error: %v", err)
		}

		// Override with flags
		overrideConfigWithFlags(cmd, cfg)

		// Force forwarding to be enabled
		if !udpForward && !tcpForward {
			cfg.Forwarder.ListenUDP = true
			cfg.Forwarder.ListenTCP = true
		}

		if verbose {
			fmt.Println(cfg.String())
		}

		// Check if license is configured for forwarder
		if cfg.License.LicenseKey != "" || cfg.License.UserToken != "" {
			// Validate license before starting forwarder
			validator := license.NewValidator(cfg.License)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			isValid, err := validator.IsValid(ctx)
			if err != nil {
				fmt.Printf("Warning: Could not validate license: %v\n", err)
				fmt.Println("DNS forwarding will continue, but some features may be restricted.")
			} else if !isValid {
				fmt.Println("ERROR: Invalid or expired license required for DNS forwarding service.")
				fmt.Println("Contact your administrator for license assistance.")
				os.Exit(1)
			} else if verbose {
				fmt.Println("✓ License validated successfully")
			}
		} else if verbose {
			fmt.Println("Note: No license configured. DNS forwarding running in compatibility mode.")
			fmt.Println("For premium features, configure SQUAWK_LICENSE_KEY or SQUAWK_USER_TOKEN.")
		}

		// Use license user token for DNS requests if available and no explicit auth token set
		if cfg.License.UserToken != "" && cfg.Client.AuthToken == "" {
			cfg.Client.AuthToken = cfg.License.UserToken
			if verbose {
				fmt.Println("Using license user token for DNS authentication")
			}
		}

		// Create DoH client
		dohClient, err := client.NewDoHClient(cfg.Client)
		if err != nil {
			log.Fatalf("Failed to create DoH client: %v", err)
		}
		defer func() {
		if err := dohClient.Close(); err != nil {
			log.Printf("Warning: failed to close DoH client: %v", err)
		}
	}()

		// Run forwarder
		runForwarder(dohClient, cfg)
	},
}

// Config command
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Configuration management commands",
	Long:  "Commands for managing configuration files and displaying current settings",
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current configuration",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := loadConfiguration()
		if err != nil {
			log.Fatalf("Configuration error: %v", err)
		}
		fmt.Println(cfg.String())
	},
}

var configEnvCmd = &cobra.Command{
	Use:   "env",
	Short: "Show supported environment variables",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Supported Environment Variables:")
		fmt.Println("=================================")
		for _, env := range config.GetEnvVarList() {
			value := os.Getenv(env)
			if value != "" {
				if strings.Contains(strings.ToLower(env), "token") {
					value = "***masked***"
				}
				fmt.Printf("%-25s = %s\n", env, value)
			} else {
				fmt.Printf("%-25s = (not set)\n", env)
			}
		}
	},
}

var configGenerateCmd = &cobra.Command{
	Use:   "generate [filename]",
	Short: "Generate example configuration file",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		filename := "squawk-client.yaml"
		if len(args) > 0 {
			filename = args[0]
		}

		cfg := config.DefaultConfig()
		cfg.Domain = "example.com"
		cfg.Client.ServerURL = "https://dns.example.com:8443"
		cfg.Client.AuthToken = "your-token-here"

		if err := config.SaveConfig(cfg, filename); err != nil {
			log.Fatalf("Failed to generate config: %v", err)
		}

		fmt.Printf("Generated example configuration: %s\n", filename)
	},
}

// Version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Squawk DNS Client (Go)\n")
		fmt.Printf("Version: %s\n", version)
		fmt.Printf("Build Time: %s\n", buildTime)
		fmt.Printf("Git Commit: %s\n", gitCommit)
	},
}

// License command
var licenseCmd = &cobra.Command{
	Use:   "license",
	Short: "License management and validation",
	Long:  "Manage and validate your Squawk DNS license and user tokens",
}

// License status command
var licenseStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check license status",
	Long:  "Validate and display current license or user token status",
	Run: func(cmd *cobra.Command, args []string) {
		// Load configuration
		cfg, err := loadConfiguration()
		if err != nil {
			log.Fatalf("Configuration error: %v", err)
		}

		// Create validator
		validator := license.NewValidator(cfg.License)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Check status
		status, err := validator.GetStatus(ctx)
		if err != nil {
			fmt.Printf("Error validating license: %v\n", err)
			os.Exit(1)
		}

		// Display status
		if status.Valid {
			fmt.Println("✓ License is valid")
		} else {
			fmt.Println("✗ License is invalid or expired")
		}

		if status.Message != "" {
			fmt.Printf("Message: %s\n", status.Message)
		}

		if status.ExpiresAt != nil {
			fmt.Printf("Expires: %s\n", *status.ExpiresAt)
		}

		if status.UserEmail != nil {
			fmt.Printf("User: %s\n", *status.UserEmail)
		}

		if status.TokensUsed != nil && status.MaxTokens != nil {
			fmt.Printf("Token Usage: %d/%d\n", *status.TokensUsed, *status.MaxTokens)
		}

		if !status.Valid {
			fmt.Println("\nContact your administrator for license assistance.")
			os.Exit(1)
		}
	},
}

// License portal command
// License portal command removed - customers should contact administrator for license assistance

func init() {
	// Add config subcommands
	configCmd.AddCommand(configShowCmd)
	configCmd.AddCommand(configEnvCmd)
	configCmd.AddCommand(configGenerateCmd)

	// Add license subcommands
	licenseCmd.AddCommand(licenseStatusCmd)
	// License portal command removed - customers should contact administrator
}