package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// DoHClient represents a DNS-over-HTTPS client with mTLS support
type DoHClient struct {
	serverURL    string
	authToken    string
	clientCert   string
	clientKey    string
	caCert       string
	verifySSL    bool
	httpClient   *http.Client
	timeout      time.Duration
}

// Config holds the configuration for the DoH client
type Config struct {
	ServerURL  string `yaml:"server_url" json:"server_url"`
	AuthToken  string `yaml:"auth_token" json:"auth_token"`
	ClientCert string `yaml:"client_cert" json:"client_cert"`
	ClientKey  string `yaml:"client_key" json:"client_key"`
	CaCert     string `yaml:"ca_cert" json:"ca_cert"`
	VerifySSL  bool   `yaml:"verify_ssl" json:"verify_ssl"`
}

// DNSResponse represents a DNS-over-HTTPS JSON response
type DNSResponse struct {
	Status   int         `json:"Status"`
	TC       bool        `json:"TC"`
	RD       bool        `json:"RD"`
	RA       bool        `json:"RA"`
	AD       bool        `json:"AD"`
	CD       bool        `json:"CD"`
	Question []DNSRecord `json:"Question,omitempty"`
	Answer   []DNSRecord `json:"Answer,omitempty"`
	Comment  string      `json:"Comment,omitempty"`
	TTL      int         `json:"TTL,omitempty"`
}

// DNSRecord represents a DNS record in the JSON response
type DNSRecord struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	TTL  int    `json:"TTL,omitempty"`
	Data string `json:"data"`
}

// NewDoHClient creates a new DNS-over-HTTPS client
func NewDoHClient(config *Config) (*DoHClient, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	client := &DoHClient{
		serverURL: config.ServerURL,
		authToken: config.AuthToken,
		clientCert: config.ClientCert,
		clientKey: config.ClientKey,
		caCert: config.CaCert,
		verifySSL: config.VerifySSL,
		timeout: 30 * time.Second,
	}

	if err := client.setupHTTPClient(); err != nil {
		return nil, fmt.Errorf("failed to setup HTTP client: %w", err)
	}

	return client, nil
}

// setupHTTPClient configures the HTTP client with mTLS support
func (c *DoHClient) setupHTTPClient() error {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: !c.verifySSL,
	}

	// Load CA certificate for server verification
	if c.caCert != "" && c.verifySSL {
		caCertData, err := os.ReadFile(c.caCert)
		if err != nil {
			return fmt.Errorf("failed to read CA certificate: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCertData) {
			return fmt.Errorf("failed to parse CA certificate")
		}
		tlsConfig.RootCAs = caCertPool
	}

	// Load client certificate for mTLS
	if c.clientCert != "" && c.clientKey != "" {
		if _, err := os.Stat(c.clientCert); err != nil {
			return fmt.Errorf("client certificate not found: %w", err)
		}
		if _, err := os.Stat(c.clientKey); err != nil {
			return fmt.Errorf("client key not found: %w", err)
		}

		cert, err := tls.LoadX509KeyPair(c.clientCert, c.clientKey)
		if err != nil {
			return fmt.Errorf("failed to load client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
		MaxIdleConns:    10,
		IdleConnTimeout: 30 * time.Second,
	}

	c.httpClient = &http.Client{
		Transport: transport,
		Timeout:   c.timeout,
	}

	return nil
}

// Query performs a DNS query using DNS-over-HTTPS
func (c *DoHClient) Query(ctx context.Context, domain, recordType string) (*DNSResponse, error) {
	if domain == "" {
		return nil, fmt.Errorf("domain cannot be empty")
	}
	if recordType == "" {
		recordType = "A"
	}

	// Build request URL with query parameters
	req, err := http.NewRequestWithContext(ctx, "GET", c.serverURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add query parameters
	q := req.URL.Query()
	q.Add("name", domain)
	q.Add("type", recordType)
	req.URL.RawQuery = q.Encode()

	// Set headers
	req.Header.Set("Accept", "application/dns-json")
	req.Header.Set("User-Agent", "Squawk DNS Client (Go/1.0)")

	// Add authentication header if token is provided
	if c.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.authToken)
	}

	// Execute request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Check status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	// Parse JSON response
	var dnsResp DNSResponse
	if err := json.Unmarshal(body, &dnsResp); err != nil {
		return nil, fmt.Errorf("failed to parse DNS response: %w", err)
	}

	return &dnsResp, nil
}

// QueryWithJSON performs a DNS query using POST with JSON payload
func (c *DoHClient) QueryWithJSON(ctx context.Context, domain, recordType string) (*DNSResponse, error) {
	if domain == "" {
		return nil, fmt.Errorf("domain cannot be empty")
	}
	if recordType == "" {
		recordType = "A"
	}

	// Create JSON payload
	payload := map[string]interface{}{
		"name": domain,
		"type": recordType,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSON: %w", err)
	}

	// Create POST request
	req, err := http.NewRequestWithContext(ctx, "POST", c.serverURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/dns-json")
	req.Header.Set("User-Agent", "Squawk DNS Client (Go/1.0)")

	// Add authentication header if token is provided
	if c.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.authToken)
	}

	// Execute request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Check status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	// Parse JSON response
	var dnsResp DNSResponse
	if err := json.Unmarshal(body, &dnsResp); err != nil {
		return nil, fmt.Errorf("failed to parse DNS response: %w", err)
	}

	return &dnsResp, nil
}

// SetTimeout sets the HTTP client timeout
func (c *DoHClient) SetTimeout(timeout time.Duration) {
	c.timeout = timeout
	if c.httpClient != nil {
		c.httpClient.Timeout = timeout
	}
}

// Close cleans up the HTTP client resources
func (c *DoHClient) Close() error {
	if c.httpClient != nil {
		c.httpClient.CloseIdleConnections()
	}
	return nil
}