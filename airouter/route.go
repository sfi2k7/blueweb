package airouter

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Add registers a new subroute with the route group
func (g *Route) Add(method, path string, handler Handler, opts ...RouteOption) *Route {
	// Lock for thread safety
	g.mu.Lock()
	defer g.mu.Unlock()

	// Create new route
	route := &Route{
		// Core properties
		Method:   method,
		Path:     g.buildPath(path),
		Handler:  handler,
		Pattern:  g.buildPattern(path),
		Priority: g.calculatePriority(path),

		// Inheritance from parent
		Middleware:  append([]Middleware{}, g.Middleware...),
		Validators:  make([]ParamValidator, len(g.Validators)),
		Constraints: make(map[string]Constraint),

		// Metadata
		Name:        "",
		Description: "",
		Version:     g.Version,
		Tags:        make([]string, 0),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),

		// Configuration
		Config: RouteConfig{
			Timeout:       g.Config.Timeout,
			MaxBodySize:   g.Config.MaxBodySize,
			RateLimit:     g.Config.RateLimit,
			CacheEnabled:  g.Config.CacheEnabled,
			CacheDuration: g.Config.CacheDuration,
			Compression:   g.Config.Compression,
		},

		// Security
		Security: &SecurityConfig{
			RequireAuth: g.Security.RequireAuth,
			Roles:       make([]string, len(g.Security.Roles)),
			Scopes:      make([]string, len(g.Security.Scopes)),
			CORS:        g.Security.CORS,
			RateLimit:   g.Security.RateLimit,
		},

		// Validation
		RequestSchema:  nil,
		ResponseSchema: nil,

		// State
		active:     true,
		deprecated: false,
		generation: g.generation,

		// Metrics
		metrics: &RouteMetrics{
			hits:         atomic.Int64{},
			latencies:    NewLatencyRecorder(),
			errors:       atomic.Int64{},
			lastAccessed: time.Now(),
		},

		// Debug
		debug:  g.debug,
		traces: make([]RouteTrace, 0),

		// Parent reference
		parent: g,
		router: g.router,

		// Concurrency
		mu: sync.RWMutex{},
	}

	// Copy parent validators
	copy(route.Validators, g.Validators)

	// Copy parent constraints
	for k, v := range g.Constraints {
		route.Constraints[k] = v
	}

	// Copy parent security roles and scopes
	copy(route.Security.Roles, g.Security.Roles)
	copy(route.Security.Scopes, g.Security.Scopes)

	// Apply options
	for _, opt := range opts {
		if err := opt(route); err != nil {
			g.router.logError("route option error", err)
		}
	}

	// Validate route
	if err := route.validate(); err != nil {
		panic(fmt.Sprintf("invalid route configuration: %v", err))
	}

	// Build route pattern
	if err := route.buildPattern(); err != nil {
		panic(fmt.Sprintf("failed to build route pattern: %v", err))
	}

	//route.Middleware...,
	// Add middlewares in correct order
	route.Middleware = append(
		g.router.globalMiddleware,
		g.Middleware...,
	)

	// Register route with router
	if err := g.router.addRoute(route); err != nil {
		panic(fmt.Sprintf("failed to register route: %v", err))
	}

	// Update metrics
	g.metrics.totalRoutes.Add(1)
	g.metrics.lastUpdated = time.Now()

	// Notify listeners
	g.notifyRouteAdded(route)

	// Add to route registry
	g.routes[route.Pattern] = route

	// Trigger optimization if needed
	if g.shouldOptimize() {
		go g.optimize()
	}

	// Cache route if enabled
	if route.Config.CacheEnabled {
		g.router.cache.Add(route.Pattern, route)
	}

	// Add debug trace
	if g.debug {
		route.addTrace(RouteTrace{
			Event: "route_added",
			Time:  time.Now(),
			Data: map[string]interface{}{
				"method":  method,
				"path":    path,
				"pattern": route.Pattern,
			},
		})
	}

	return route
}

// Helper types and constants

type RouteOption func(*Route) error

type RouteConfig struct {
	Timeout       time.Duration
	MaxBodySize   int64
	RateLimit     *RateLimit
	CacheEnabled  bool
	CacheDuration time.Duration
	Compression   string
}

type SecurityConfig struct {
	RequireAuth bool
	Roles       []string
	Scopes      []string
	CORS        *CORSConfig
	RateLimit   *RateLimit
}

type RouteMetrics struct {
	hits         atomic.Int64
	latencies    *LatencyRecorder
	errors       atomic.Int64
	lastAccessed time.Time
}

type RouteTrace struct {
	Event string
	Time  time.Time
	Data  map[string]interface{}
}

type Constraint struct {
	Pattern   string
	Validator func(string) bool
	Message   string
}

// // Example usage:
// func main() {
//     router := NewRouter()

//     // Create route group
//     api := router.Group("/api/v1")

//     // Add route with options
//     api.Add("GET", "/users/{id}", handleUser,
//         WithName("get_user"),
//         WithDescription("Get user by ID"),
//         WithTags("users", "api"),
//         WithTimeout(5*time.Second),
//         WithRateLimit(100, time.Minute),
//         WithCaching(time.Minute),
//         WithRoles("admin", "user"),
//         WithValidation(userSchema),
//         WithMiddleware(LogMiddleware, AuthMiddleware),
//     )
// }
