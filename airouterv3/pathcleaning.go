package airouterv3

import (
	"net/url"
	"path"
	"strings"
	"unicode"
)

// PathConfig holds configuration for path normalization
type PathConfig struct {
	CleanPath              bool // Remove dot segments and duplicate slashes
	RemoveTrailingSlash    bool // Remove trailing slash
	RedirectTrailingSlash  bool // Redirect if trailing slash does not match route
	RedirectFixedPath      bool // Redirect to cleaned path
	HandleMethodNotAllowed bool // Return 405 instead of 404 if method not allowed
	CaseInsensitive        bool // Case insensitive path matching
}

// DefaultPathConfig provides default path configuration
var DefaultPathConfig = PathConfig{
	CleanPath:              true,
	RemoveTrailingSlash:    false,
	RedirectTrailingSlash:  true,
	RedirectFixedPath:      true,
	HandleMethodNotAllowed: true,
	CaseInsensitive:        true,
}

// isValidPath checks if the path contains only valid characters
func isValidPath(path string) bool {
	for _, r := range path {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) &&
			!strings.ContainsRune("/-_.~:@!$&'()*+,;=", r) {
			return false
		}
	}
	return true
}

// Path utility methods
func (pu *PathUtils) Join(segments ...string) string {
	return path.Join(segments...)
}

func (pu *PathUtils) Clean(p string) string {
	return path.Clean(p)
}

func (pu *PathUtils) Split(p string) []string {
	return strings.Split(strings.Trim(p, "/"), "/")
}

func (pu *PathUtils) Base(p string) string {
	return path.Base(p)
}

func (pu *PathUtils) Dir(p string) string {
	return path.Dir(p)
}

func (pu *PathUtils) HasPrefix(path, prefix string) bool {
	return strings.HasPrefix(path, prefix)
}

func (pu *PathUtils) HasSuffix(path, suffix string) bool {
	return strings.HasSuffix(path, suffix)
}

// Additional path utilities
func (pu *PathUtils) AddTrailingSlash(p string) string {
	if !strings.HasSuffix(p, "/") {
		return p + "/"
	}
	return p
}

func (pu *PathUtils) RemoveTrailingSlash(p string) string {
	return strings.TrimRight(p, "/")
}

func (pu *PathUtils) NormalizeSeparators(p string) string {
	return strings.ReplaceAll(p, "\\", "/")
}

func (pu *PathUtils) IsAbsolute(p string) bool {
	return strings.HasPrefix(p, "/")
}

// PathUtils provides utility functions for path manipulation
type PathUtils struct{}

// Add these methods to Router
func (r *Router) PathUtils() *PathUtils {
	return &PathUtils{}
}

// cleanPath cleans and normalizes the path
func (r *Router) cleanPath(p string) string {
	if !r.pathConfig.CleanPath {
		return p
	}

	// Convert encoded characters
	decoded, err := url.PathUnescape(p)
	if err != nil {
		return p
	}

	// Use path.Clean to remove . and .. segments
	cleaned := path.Clean(decoded)

	// Ensure path starts with /
	if !strings.HasPrefix(cleaned, "/") {
		cleaned = "/" + cleaned
	}

	// Handle trailing slash based on configuration
	if r.pathConfig.RemoveTrailingSlash {
		cleaned = strings.TrimRight(cleaned, "/")
	}

	// Normalize case if configured
	if r.pathConfig.CaseInsensitive {
		cleaned = strings.ToLower(cleaned)
	}

	// Re-encode special characters
	encoded := url.PathEscape(cleaned)
	encoded = strings.ReplaceAll(encoded, "%2F", "/") // Keep slashes readable

	return encoded
}

// normalizePath normalizes the path and handles redirects
func (r *Router) normalizePath(path string) (string, bool) {
	if !r.pathConfig.CleanPath {
		return path, false
	}

	cleaned := r.cleanPath(path)

	// Check if we need to redirect
	if r.pathConfig.RedirectFixedPath && cleaned != path {
		return cleaned, true
	}

	return cleaned, false
}

// Add configuration methods
func (r *Router) SetPathConfig(config PathConfig) {
	r.pathConfig = config
}

// Helper methods for path configuration
func (r *Router) EnableTrailingSlash() {
	r.pathConfig.RemoveTrailingSlash = false
	r.pathConfig.RedirectTrailingSlash = true
}

func (r *Router) DisableTrailingSlash() {
	r.pathConfig.RemoveTrailingSlash = true
	r.pathConfig.RedirectTrailingSlash = false
}

func (r *Router) EnableCaseInsensitive() {
	r.pathConfig.CaseInsensitive = true
}

func (r *Router) DisableCaseInsensitive() {
	r.pathConfig.CaseInsensitive = false
}
