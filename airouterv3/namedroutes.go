package airouterv3

import (
	"fmt"
	"strings"
)

type RouteInfo struct {
	path       string
	params     []string // stores parameter names
	isWildcard bool
}

// Helper function to extract parameter names from path
func extractParams(path string) []string {
	var params []string
	segments := strings.Split(path, "/")
	for _, segment := range segments {
		if strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}") {
			param := strings.Trim(segment, "{}")
			params = append(params, param)
		}
	}
	return params
}

func (r *Router) Name(name string) *Router {
	if r.lastPath != "" {
		r.namedRoutes[name] = RouteInfo{
			path:       r.lastPath,
			params:     extractParams(r.lastPath),
			isWildcard: strings.Contains(r.lastPath, "*"),
		}
	}
	return r
}

// URL generates a URL for a named route with given parameters
func (r *Router) URL(name string, params map[string]string) (string, error) {
	route, exists := r.namedRoutes[name]
	if !exists {
		return "", fmt.Errorf("route '%s' not found", name)
	}

	path := route.path
	for _, param := range route.params {
		value, exists := params[param]
		if !exists {
			return "", fmt.Errorf("parameter '%s' not provided for route '%s'", param, name)
		}
		path = strings.Replace(path, "{"+param+"}", value, 1)
	}

	return path, nil
}

// Reverse routing with query parameters
func (r *Router) URLWithQuery(name string, params map[string]string, query map[string]string) (string, error) {
	url, err := r.URL(name, params)
	if err != nil {
		return "", err
	}

	if len(query) > 0 {
		values := make([]string, 0, len(query))
		for k, v := range query {
			values = append(values, fmt.Sprintf("%s=%s", k, v))
		}
		url += "?" + strings.Join(values, "&")
	}

	return url, nil
}

// Check if route exists
func (r *Router) HasRoute(name string) bool {
	_, exists := r.namedRoutes[name]
	return exists
}

// Get all named routes
func (r *Router) GetNamedRoutes() map[string]RouteInfo {
	return r.namedRoutes
}
