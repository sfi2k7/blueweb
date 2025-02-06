package airouterv3

import (
	"net/http"
	"strings"
)

type CORSConfig struct {
	AllowOrigins     []string
	AllowMethods     []string
	AllowHeaders     []string
	ExposeHeaders    []string
	AllowCredentials bool
	MaxAge           int // in seconds
}

// Default CORS configuration
var defaultCORSConfig = &CORSConfig{
	AllowOrigins:     []string{"*"},
	AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"},
	AllowHeaders:     []string{"Origin", "Content-Length", "Content-Type", "Authorization"},
	ExposeHeaders:    []string{},
	AllowCredentials: false,
	MaxAge:           86400, // 24 hours
}

// EnableAutomaticOPTIONS enables or disables automatic OPTIONS handling
func (r *Router) EnableAutomaticOPTIONS(enable bool) {
	r.automaticOPTIONS = enable
}

// SetCORSConfig sets custom CORS configuration
func (r *Router) SetCORSConfig(config *CORSConfig) {
	r.corsConfig = config
}

// getAllowedMethods returns all methods allowed for a path
func (r *Router) getAllowedMethods(path string) []string {
	return []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete}
	//TODO:
	// node, _ := r.findRoute(path)
	// if node == nil {
	// 	return nil
	// }

	// methods := make([]string, 0)
	// for method := range node.handlers {
	// 	methods = append(methods, method)
	// }
	// return methods
}

// handleCORS handles CORS headers
func (r *Router) handleCORS(c *Context) {
	if r.corsConfig == nil {
		return
	}

	origin := c.Request.Header.Get("Origin")
	if origin == "" {
		return
	}

	// Check if origin is allowed
	allowOrigin := "*"
	if len(r.corsConfig.AllowOrigins) > 0 && r.corsConfig.AllowOrigins[0] != "*" {
		allowOrigin = ""
		for _, o := range r.corsConfig.AllowOrigins {
			if o == origin {
				allowOrigin = origin
				break
			}
		}
		if allowOrigin == "" {
			return
		}
	}

	header := c.ResponseWriter.Header()
	header.Set("Access-Control-Allow-Origin", allowOrigin)

	if r.corsConfig.AllowCredentials {
		header.Set("Access-Control-Allow-Credentials", "true")
	}

	if c.Request.Method == http.MethodOptions {
		// Handle preflight request
		if r.corsConfig.MaxAge > 0 {
			header.Set("Access-Control-Max-Age", string(r.corsConfig.MaxAge))
		}

		// Get allowed methods for this path
		methods := r.getAllowedMethods(c.Request.URL.Path)
		if len(methods) > 0 {
			header.Set("Access-Control-Allow-Methods", strings.Join(methods, ", "))
		} else if len(r.corsConfig.AllowMethods) > 0 {
			header.Set("Access-Control-Allow-Methods", strings.Join(r.corsConfig.AllowMethods, ", "))
		}

		// Handle Allow-Headers
		reqHeaders := c.Request.Header.Get("Access-Control-Request-Headers")
		if reqHeaders != "" {
			header.Set("Access-Control-Allow-Headers", reqHeaders)
		} else if len(r.corsConfig.AllowHeaders) > 0 {
			header.Set("Access-Control-Allow-Headers", strings.Join(r.corsConfig.AllowHeaders, ", "))
		}
	} else if len(r.corsConfig.ExposeHeaders) > 0 {
		// Handle simple request
		header.Set("Access-Control-Expose-Headers", strings.Join(r.corsConfig.ExposeHeaders, ", "))
	}
}

// Additional
// CORS configuration helpers
func (r *Router) AllowOrigin(origins ...string) {
	if r.corsConfig == nil {
		r.corsConfig = &CORSConfig{}
	}
	r.corsConfig.AllowOrigins = origins
}

func (r *Router) AllowMethods(methods ...string) {
	if r.corsConfig == nil {
		r.corsConfig = &CORSConfig{}
	}
	r.corsConfig.AllowMethods = methods
}

func (r *Router) AllowHeaders(headers ...string) {
	if r.corsConfig == nil {
		r.corsConfig = &CORSConfig{}
	}
	r.corsConfig.AllowHeaders = headers
}

func (r *Router) ExposeHeaders(headers ...string) {
	if r.corsConfig == nil {
		r.corsConfig = &CORSConfig{}
	}
	r.corsConfig.ExposeHeaders = headers
}

func (r *Router) AllowCredentials(allow bool) {
	if r.corsConfig == nil {
		r.corsConfig = &CORSConfig{}
	}
	r.corsConfig.AllowCredentials = allow
}

func (r *Router) SetMaxAge(seconds int) {
	if r.corsConfig == nil {
		r.corsConfig = &CORSConfig{}
	}
	r.corsConfig.MaxAge = seconds
}
