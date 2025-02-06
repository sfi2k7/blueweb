package airouter

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type (
	Router struct {
		// Core components
		tree       *node
		trees      map[string]*node              // Method -> tree root node mapping
		routes     map[string]*Route             // Pattern -> route mapping
		handlers   map[string]map[string]Handler // Method -> path -> handler mapping
		middleware []middlewareEntry             // Global middleware stack

		// Configuration
		config    RouterConfig // Router configuration
		maxParams int          // Maximum number of parameters per route
		pool      *sync.Pool   // Context object pool

		// Concurrency control
		mu      sync.RWMutex // Router mutex for thread safety
		routeMu sync.RWMutex // Route operations mutex
		poolMu  sync.RWMutex // Pool operations mutex

		// Error handling
		notFound         Handler                   // 404 handler
		methodNotAllowed Handler                   // 405 handler
		panicHandler     func(interface{}) Handler // Panic recovery handler
		errorHandler     func(error) Handler       // Error handler

		// Metrics and monitoring
		// metrics  *RouterMetrics  // Router metrics
		// profiler *RouterProfiler // Performance profiler
		// logger   Logger          // Router logger

		// Features
		cache *RouterCache // Route cache
		// validator *ParamValidator // Parameter validator
		// optimizer  *TreeOptimizer  // Tree optimizer
		// compressor *PathCompressor // Path compressor

		// WebSocket support
		// websockets map[string]*WebSocketManager // WebSocket handlers
		// upgrader   *websocket.Upgrader          // WebSocket upgrader

		// Hot reload support
		// reloader   *HotReloader // Hot reload manager
		generation int // Router generation (for reload)

		// Template engine
		// templates *TemplateEngine // Template rendering engine
		viewPath string // View templates path

		// Security
		// cors      *CORSConfig     // CORS configuration
		// security  *SecurityConfig // Security settings
		// rateLimit *RateLimiter    // Rate limiting

		// Static file serving
		// static      *StaticFileServer // Static file server
		staticPaths map[string]string // Static path mappings

		// Events and hooks
		// listeners []RouterListener  // Router event listeners
		// hooks     map[string][]Hook // Router hooks

		// Debug and development
		debug   bool // Debug mode flag
		devMode bool // Development mode flag
		// traces  []RouteTrace // Request traces

		// Resources and cleanup
		// resources *ResourceManager // Resource manager
		// cleanup   *CleanupManager  // Cleanup manager

		// State and monitoring
		// state   *RouterState   // Router state
		// health  *HealthChecker // Health checker
		// monitor *RouterMonitor // Router monitor

		// Additional features
		// params   *ParamStore            // Parameter store
		// groups   map[string]*RouteGroup // Route groups
		aliases  map[string]string // Route aliases
		rewrites map[string]string // URL rewrites

		// Performance optimization
		// cache2    *SecondaryCache  // Secondary cache
		fastMatch map[string]*node // Fast path matching
		optimized map[string]bool  // Optimization status

		// Statistics
		// stats    *RouterStats           // Router statistics
		counters *atomic.Value          // Atomic counters
		timers   map[string]*time.Timer // Various timers

		// Startup and shutdown
		startTime  time.Time     // Router start time
		shutdownCh chan struct{} // Shutdown channel
		doneCh     chan struct{} // Done channel

		// Configuration and settings
		settings map[string]interface{} // Generic settings
		flags    uint32                 // Feature flags
		// options  *RouterOptions         // Router options

		// Extensions
		extensions map[string]interface{} // Router extensions
		// plugins    map[string]Plugin      // Router plugins

		// Internationalization
		// i18n    *I18nManager       // Internationalization manager
		// locales map[string]*Locale // Available locales

		// Testing and mocking
		testing bool               // Testing mode flag
		mocks   map[string]Handler // Mock handlers

		// Documentation
		// docs    *RouterDocs             // Router documentation
		// schemas map[string]*RouteSchema // Route schemas

		// Version control
		version string // Router version
		// buildInfo *BuildInfo // Build information

		// Context management
		contextPool *sync.Pool // Context object pool
		varsPool    *sync.Pool // Variables pool

		// System integration
		signals chan os.Signal // System signals
		pidFile string         // PID file path

		// Custom fields
		custom map[string]interface{} // Custom user fields

		paths       *StringMap  // Pre-compiled paths
		maxBodySize int64       // Maximum request body size
		bodyPool    sync.Pool   // Body buffer pool
		routeCache  *RouteCache // Thread-safe route cache
		regexCache  map[string]*regexp.Regexp
	}

	// // Router is the main router structure
	// Router struct {
	// 	tree        *node
	// 	pool        sync.Pool
	// 	cache       Cache      // Route cache
	// 	paths       *StringMap // Pre-compiled paths
	// 	maxBodySize int64      // Maximum request body size
	// 	bodyPool    sync.Pool  // Body buffer pool
	// 	regexCache  map[string]*regexp.Regexp
	// 	routeCache  *RouteCache
	// 	optimized   bool
	// 	middleware  []middlewareEntry
	// 	config      struct {
	// 		TrailingSlash         bool
	// 		OptimizationThreshold int
	// 		Debug                 bool
	// 	}
	// 	maxParams int
	// 	mu        sync.RWMutex
	// }
)

// // Cache implementation
// type RouterCache struct {
// 	cache sync.Map
// }

// func (c *RouterCache) Get(key string) (interface{}, bool) {
// 	return c.cache.Load(key)
// }

// func (c *RouterCache) Set(key string, value interface{}) {
// 	c.cache.Store(key, value)
// }

// func (c *RouterCache) Delete(key string) {
// 	c.cache.Delete(key)
// }

// NewRouter creates a new router instance
func NewRouter() *Router {
	r := &Router{
		// tree: &node{
		// 	path:     "/",
		// 	handlers: make(map[string][]Handler),
		// },
		cache:       &RouterCache{},
		maxBodySize: 10 << 20, // 10 MB
	}

	r.bodyPool.New = func() interface{} {
		return make([]byte, 32*1024) // 32 KB
	}

	r.pool.New = func() interface{} {
		return &Context{
			params: make(map[string]string),
		}
	}

	return r
}

// // optimizeTree optimizes the routing tree
// func (r *Router) optimizeTree() {
// 	if r.tree == nil {
// 		return
// 	}

// 	config := OptimizationConfig{
// 		MergeCommonPrefixes: true,
// 		SortByPriority:      true,
// 		CompressChains:      true,
// 		RemoveEmptyNodes:    true,
// 		CacheRoutes:         true,
// 	}

// 	r.tree = r.tree.optimize(config)
// }

// findRoute updated to support regex matching
func (r *Router) findRoute(path string) (*node, *Params) {
	segments := strings.Split(strings.Trim(path, "/"), "/")
	current := r.tree

	params := &Params{}

	for i, segment := range segments {
		matched := false

		for _, child := range current.children {
			if child.isCatchAll {
				params.Add("path", strings.Join(segments[i:], "/"))
				return child, params
			}

			if child.path == segment {
				current = child
				matched = true
				break
			}

			if child.isParam {
				// Check regex if present
				if child.paramDef.Regex != nil {
					if !child.paramDef.Regex.MatchString(segment) {
						if child.paramDef.IsOptional {
							params.Add(child.paramDef.Name, child.paramDef.DefaultValue)
							matched = true
							break
						}
						continue
					}
				}

				params.Add(child.paramDef.Name, segment)
				current = child
				matched = true
				break
			}
		}

		if !matched {
			return nil, nil
		}
	}

	return current, params
}

// Helper methods for common regex patterns
type RoutePatterns struct {
	router *Router
	path   string
}

func (r *Router) Pattern(path string) *RoutePatterns {
	return &RoutePatterns{router: r, path: path}
}

func (rp *RoutePatterns) Int(param string) *RoutePatterns {
	return rp.Regex(param, "\\d+")
}

func (rp *RoutePatterns) Alpha(param string) *RoutePatterns {
	return rp.Regex(param, "[a-zA-Z]+")
}

func (rp *RoutePatterns) Alphanum(param string) *RoutePatterns {
	return rp.Regex(param, "[a-zA-Z0-9]+")
}

func (rp *RoutePatterns) Regex(param, pattern string) *RoutePatterns {
	rp.path = strings.Replace(rp.path, "{"+param+"}", "{"+param+":"+pattern+"}", 1)
	return rp
}

func (rp *RoutePatterns) Optional(param, defaultValue string) *RoutePatterns {
	rp.path = strings.Replace(rp.path, "{"+param+"}", "{"+param+"?:.*:"+defaultValue+"}", 1)
	return rp
}

func (rp *RoutePatterns) Enum(param string, values ...string) *RoutePatterns {
	pattern := strings.Join(values, "|")
	return rp.Regex(param, pattern)
}

// Handler methods
func (rp *RoutePatterns) Get(handler Handler) {
	rp.router.Get(rp.path, handler)
}

func (rp *RoutePatterns) Post(handler Handler) {
	rp.router.Post(rp.path, handler)
}

// // FindRoute with caching
// func (r *Router) findRoute(path string) (*node, *Params) {
// 	// Check cache first
// 	if r.routeCache != nil {
// 		if cached, ok := r.routeCache.Get(path); ok {
// 			return cached, extractParams(cached, path)
// 		}
// 	}

// 	params := &Params{}
// 	// Normal route finding
// 	node := r.tree.findRoute(path, params)

// 	// Cache the result
// 	if node != nil && r.routeCache != nil {
// 		r.routeCache.Set(path, node)
// 	}

// 	return node, params
// }

func (r *Router) analyzeTree() RouteStats {
	stats := RouteStats{}
	r.tree.analyze(&stats, 0)
	return stats
}

// Group creates a new route group
func (r *Router) Group(prefix string) *Route {
	return &Route{
		prefix: prefix,
		router: r,
	}
}

// executeMiddleware executes the middleware chain
func (r *Router) executeMiddleware(ctx *Context, middleware []middlewareEntry) bool {
	for _, m := range middleware {
		if ctx.aborted {
			return false
		}

		proceed := m.handler(ctx)
		if !proceed && !m.must {
			return false
		}
	}
	return true
}

// Add method updated to support regex
func (r *Router) Add(method, path string, handlers ...Handler) error {
	segments := strings.Split(strings.Trim(path, "/"), "/")
	current := r.tree

	for _, segment := range segments {
		isParam := strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}")
		isCatchAll := segment == "*path"

		var paramDef *ParamDefinition
		if isParam {
			var err error
			paramDef, err = parseParam(segment)
			if err != nil {
				return fmt.Errorf("invalid parameter pattern '%s': %v", segment, err)
			}
		}

		var child *node
		for _, n := range current.children {
			if n.path == segment {
				child = n
				break
			}
		}

		if child == nil {
			child = &node{
				path:       segment,
				isParam:    isParam,
				isCatchAll: isCatchAll,
				paramDef:   paramDef,
				handlers:   make(map[string][]Handler),
			}
			current.children = append(current.children, child)
		}

		current = child
	}

	current.handlers[method] = handlers
	return nil
}

// // Add registers a new route with the router
// func (r *Router) Add(method, path string, handler Handler, middlewares ...Middleware) error {
// 	r.mu.Lock()
// 	defer r.mu.Unlock()

// 	// Validate inputs
// 	if err := r.validateRoute(method, path, handler); err != nil {
// 		return err
// 	}

// 	// Normalize path
// 	normalizedPath := r.normalizePath(path)

// 	// Check for duplicates
// 	if r.isDuplicateRoute(method, normalizedPath) {
// 		return fmt.Errorf("route already exists: %s %s", method, path)
// 	}

// 	// Create or get tree root for method
// 	if r.trees[method] == nil {
// 		r.trees[method] = &node{
// 			router:     r,
// 			segment:    "/",
// 			nodeType:   staticNode,
// 			children:   make([]*node, 0),
// 			handlers:   make(map[string]Handler),
// 			middleware: make([]Middleware, 0),
// 		}
// 	}

// 	// Parse path into segments
// 	segments := r.parsePathSegments(normalizedPath)

// 	// Build route metadata
// 	route := &Route{
// 		Method:     method,
// 		Path:       normalizedPath,
// 		Handler:    handler,
// 		Middleware: middlewares,
// 		Pattern:    r.buildRoutePattern(segments),
// 		Priority:   r.calculateRoutePriority(segments),
// 		CreatedAt:  time.Now(),
// 		MaxParams:  r.countParams(segments),
// 	}

// 	// Add route to tree
// 	currentNode := r.trees[method]
// 	finalNode, err := r.insertRoute(currentNode, segments, 0)
// 	if err != nil {
// 		return err
// 	}

// 	// Set handler and middleware on final node
// 	finalNode.handler = handler
// 	finalNode.middleware = middlewares
// 	finalNode.route = route
// 	finalNode.fullPath = normalizedPath

// 	// Update route registry
// 	r.routes[route.Pattern] = route

// 	// Update metrics
// 	r.updateRouteMetrics(route)

// 	// Trigger optimization if needed
// 	if r.shouldOptimize() {
// 		go r.optimizeTree()
// 	}

// 	// Notify listeners
// 	r.notifyRouteAdded(route)

// 	return nil
// }

// Helper methods

// func (r *Router) validateRoute(method, path string, handler Handler) error {
// 	if method == "" {
// 		return errors.New("method cannot be empty")
// 	}
// 	if path == "" {
// 		return errors.New("path cannot be empty")
// 	}
// 	if handler == nil {
// 		return errors.New("handler cannot be nil")
// 	}

// 	if !r.isValidMethod(method) {
// 		return fmt.Errorf("invalid HTTP method: %s", method)
// 	}

// 	if !r.isValidPath(path) {
// 		return fmt.Errorf("invalid path format: %s", path)
// 	}
// 	return nil
// }

func (r *Router) normalizePath(path string) string {
	// Ensure leading slash
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	// Remove trailing slash if configured
	if !r.config.TrailingSlash && len(path) > 1 && strings.HasSuffix(path, "/") {
		path = path[:len(path)-1]
	}

	// Clean path
	return filepath.Clean(path)
}

func (r *Router) parsePathSegments(path string) []pathSegment {
	segments := make([]pathSegment, 0)
	parts := strings.Split(strings.Trim(path, "/"), "/")

	for _, part := range parts {
		segment := pathSegment{
			value:   part,
			segtype: staticSegment,
		}

		// Check for parameter segments
		if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
			segment.segtype = paramSegment
			segment.paramName = strings.Trim(part, "{}")
		}

		// Check for catch-all segments
		if strings.HasPrefix(part, "*") {
			segment.segtype = catchAllSegment
			segment.paramName = strings.TrimPrefix(part, "*")
		}

		segments = append(segments, segment)
	}

	return segments
}

// func (r *Router) insertRoute(n *node, segments []pathSegment, index int) (*node, error) {
// 	// Base case: all segments processed
// 	if index >= len(segments) {
// 		return n, nil
// 	}

// 	segment := segments[index]
// 	var child *node

// 	// Find or create appropriate child node
// 	switch segment.segtype {
// 	case staticSegment:
// 		child = n.getStaticChild(segment.value)
// 		if child == nil {
// 			child = &node{
// 				router:     r,
// 				segment:    segment.value,
// 				nodeType:   staticNode,
// 				children:   make([]*node, 0),
// 				handlers:   make(map[string][]Handler),
// 				middleware: make([]Middleware, 0),
// 			}

// 			n.children = append(n.children, child)
// 		}

// 	case paramSegment:
// 		child = node.getParamChild()
// 		if child == nil {
// 			child = &node{
// 				router:     r,
// 				segment:    segment.value,
// 				nodeType:   paramNode,
// 				paramName:  segment.paramName,
// 				children:   make([]*node, 0),
// 				handlers:   make(map[string]Handler),
// 				middleware: make([]Middleware, 0),
// 			}
// 			node.children = append(node.children, child)
// 		}

// 	case catchAllSegment:
// 		if index != len(segments)-1 {
// 			return nil, fmt.Errorf("catch-all route must be at path end: %s", segment.value)
// 		}
// 		child = &node{
// 			router:     r,
// 			segment:    segment.value,
// 			nodeType:   catchAllNode,
// 			paramName:  segment.paramName,
// 			children:   make([]*node, 0),
// 			handlers:   make(map[string]Handler),
// 			middleware: make([]Middleware, 0),
// 		}
// 		node.children = append(node.children, child)
// 	}

// 	// Recursively process remaining segments
// 	return r.insertRoute(child, segments, index+1)
// }

func (r *Router) calculateRoutePriority(segments []pathSegment) int {
	priority := len(segments) * 10 // Base priority on path length

	// Adjust priority based on segment types
	for _, segment := range segments {
		switch segment.segtype {
		case staticSegment:
			priority += 10 // Static segments get highest priority
		case paramSegment:
			priority += 5 // Parameter segments get medium priority
		case catchAllSegment:
			priority += 1 // Catch-all segments get lowest priority
		}
	}

	return priority
}

// func (r *Router) updateRouteMetrics(route *Route) {
// 	r.metrics.mu.Lock()
// 	defer r.metrics.mu.Unlock()

// 	r.metrics.totalRoutes++
// 	r.metrics.routesByMethod[route.Method]++
// 	r.metrics.lastUpdated = time.Now()

// 	// Update parameter statistics
// 	if route.MaxParams > r.metrics.maxParams {
// 		r.metrics.maxParams = route.MaxParams
// 	}
// }

// func (r *Router) shouldOptimize() bool {
// 	r.metrics.mu.RLock()
// 	defer r.metrics.mu.RUnlock()

// 	// Check if tree needs optimization based on metrics
// 	if r.metrics.totalRoutes > r.config.OptimizationThreshold {
// 		return true
// 	}

// 	return false
// }

// func (r *Router) notifyRouteAdded(route *Route) {
// 	for _, listener := range r.listeners {
// 		go func(l RouterListener, r *Route) {
// 			if err := l.OnRouteAdded(r); err != nil {
// 				r.router.logError("route listener error", err)
// 			}
// 		}(listener, route)
// 	}
// }

// Use adds optional middleware
func (r *Router) Use(middleware ...Middleware) {
	for _, m := range middleware {
		r.middleware = append(r.middleware, middlewareEntry{handler: m, must: false})
	}
}

// Must adds required middleware
func (r *Router) Must(middleware ...Middleware) {
	for _, m := range middleware {
		r.middleware = append(r.middleware, middlewareEntry{handler: m, must: true})
	}
}

// Use adds optional middleware to a route group
func (g *Route) Use(middleware ...Middleware) *Route {
	for _, m := range middleware {
		g.middleware = append(g.middleware, middlewareEntry{handler: m, must: false})
	}
	return g
}

// Must adds required middleware to a route group
func (g *Route) Must(middleware ...Middleware) *Route {
	for _, m := range middleware {
		g.middleware = append(g.middleware, middlewareEntry{handler: m, must: true})
	}
	return g
}

// Helper methods for HTTP verbs
func (r *Router) Get(path string, handler Handler)    { r.Add(http.MethodGet, path, handler) }
func (r *Router) Post(path string, handler Handler)   { r.Add(http.MethodPost, path, handler) }
func (r *Router) Put(path string, handler Handler)    { r.Add(http.MethodPut, path, handler) }
func (r *Router) Delete(path string, handler Handler) { r.Add(http.MethodDelete, path, handler) }

// ServeHTTP implements http.Handler interface
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	ctx := r.pool.Get().(*Context)
	ctx.Reset(w, req)
	ctx.router = r
	defer r.pool.Put(ctx)

	segments := strings.Split(strings.Trim(req.URL.Path, "/"), "/")
	current := r.tree
	remainingPath := ""

	for i, segment := range segments {
		matched := false

		for _, child := range current.children {
			if child.isCatchAll {
				remainingPath = strings.Join(segments[i:], "/")
				current = child
				matched = true
				break
			}

			if child.path == segment || child.isParam {
				if child.isParam {
					paramName := strings.Trim(child.path, "{}")
					ctx.params[paramName] = segment
				}
				current = child
				matched = true
				break
			}
		}

		if !matched {
			http.NotFound(w, req)
			return
		}
	}

	if remainingPath != "" {
		ctx.params["path"] = remainingPath
	}

	handler, ok := current.handlers[req.Method]
	if !ok {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	handler[0](ctx)
}
