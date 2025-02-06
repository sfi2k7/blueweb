package airouterv3

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"

	"golang.org/x/crypto/acme/autocert"
)

// Add these types to the Router struct
type SSLConfig struct {
	Enabled     bool
	Certificate string
	PrivateKey  string
	AutoTLS     bool
	Domains     []string
	CertCache   string
}

// Helper method to create SSL config
func NewSSLConfig() *SSLConfig {
	return &SSLConfig{
		Enabled: false,
	}
}

// Configure manual SSL
func (c *SSLConfig) WithCertificate(certFile, keyFile string) *SSLConfig {
	c.Enabled = true
	c.AutoTLS = false
	c.Certificate = certFile
	c.PrivateKey = keyFile
	return c
}

// Configure Auto SSL with Let's Encrypt
func (c *SSLConfig) WithAutoTLS(domains []string, cacheDir string) *SSLConfig {
	c.Enabled = true
	c.AutoTLS = true
	c.Domains = domains
	c.CertCache = cacheDir
	return c
}

// serveAutoTLS starts the server with automatic SSL certificate management
func (r *Router) serveAutoTLS(server *http.Server, config *SSLConfig) error {
	if len(config.Domains) == 0 {
		return fmt.Errorf("no domains specified for AutoTLS")
	}

	certManager := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(config.Domains...),
	}

	// Set certificate cache directory if specified
	if config.CertCache != "" {
		certManager.Cache = autocert.DirCache(config.CertCache)
	}

	// Configure TLS
	server.TLSConfig = &tls.Config{
		GetCertificate: certManager.GetCertificate,
		MinVersion:     tls.VersionTLS12,
	}

	// Start HTTP-01 challenge handler
	go func() {
		log.Printf("Starting HTTP-01 challenge handler on :80")
		if err := http.ListenAndServe(":80", certManager.HTTPHandler(nil)); err != nil {
			log.Printf("HTTP-01 challenge handler error: %v", err)
		}
	}()

	log.Printf("Starting HTTPS server on %s", server.Addr)
	return server.ListenAndServeTLS("", "")
}

// serveManualTLS starts the server with manual SSL certificate management
func (r *Router) serveManualTLS(server *http.Server, config *SSLConfig) error {
	if config.Certificate == "" || config.PrivateKey == "" {
		return fmt.Errorf("certificate and private key files are required for manual TLS")
	}

	// Configure TLS
	server.TLSConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	log.Printf("Starting HTTPS server on %s", server.Addr)
	return server.ListenAndServeTLS(config.Certificate, config.PrivateKey)
}
