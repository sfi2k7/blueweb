package airtouter2

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Params holds URL parameters
type Params struct {
	params    map[string]string
	maxParams int
}

// NewParams creates a new parameter store
func NewParams(maxParams int) *Params {
	return &Params{
		params:    make(map[string]string, maxParams),
		maxParams: maxParams,
	}
}

// Add adds a parameter
func (p *Params) Add(name, value string) {
	if len(p.params) < p.maxParams {
		p.params[name] = value
	}
}

// Get retrieves a parameter value
func (p *Params) Get(name string) string {
	return p.params[name]
}

// GetAll returns all parameters
func (p *Params) GetAll() map[string]string {
	return p.params
}

// Reset clears all parameters
func (p *Params) Reset() {
	for k := range p.params {
		delete(p.params, k)
	}
}

// Count returns number of parameters
func (p *Params) Count() int {
	return len(p.params)
}

type (
	// Handler defines a standard http handler function
	Handler func(*Context)

	// Middleware defines a middleware handler function
	Middleware func(*Context) bool

	// Context represents the request context
	Context struct {
		Request        *http.Request
		ResponseWriter http.ResponseWriter
		params         *Params     // Thread-safe parameter storage
		store          sync.Map    // Thread-safe key-value store
		index          int32       // Current handler index
		handlers       []Handler   // Handler chain
		aborted        atomic.Bool // Abort flag
		errors         []error     // Error stack
		router         *Router     // Reference to router

		bodyParsed    bool
		jsonData      map[string]interface{}
		formData      url.Values
		multipartForm *multipart.Form
		maxMemory     int64
		err           error

		query         map[string][]string
		queryParsed   bool
		headers       map[string][]string
		headersParsed bool
		start         time.Time
	}

	// Router is the main router struct
	Router struct {
		tree             *node
		pool             sync.Pool
		middleware       []Middleware
		errorHandler     ErrorHandler
		notFound         Handler
		methodNotAllowed Handler
		config           *Config
		metrics          *Metrics
		//mu               sync.RWMutex
		cache         *routeCache
		maxParams     int
		errorHandlers map[int]ErrorHandler // Status code specific handlers

		// Core components
		//tree       *node
		trees    map[string]*node              // Method -> tree root node mapping
		routes   map[string]*Route             // Pattern -> route mapping
		handlers map[string]map[string]Handler // Method -> path -> handler mapping
		//middleware []middlewareEntry             // Global middleware stack

		// Configuration
		//conf//ig    RouterConfig // Router configuration
		//ma//xParams int          // Maximum number of parameters per route
		//pool      *sync.Pool   // Context object pool

		// Concurrency control
		mu      sync.RWMutex // Router mutex for thread safety
		routeMu sync.RWMutex // Route operations mutex
		poolMu  sync.RWMutex // Pool operations mutex

		// Error handling
		// notFound         Handler                   // 404 handler
		// methodNotAllowed Handler                   // 405 handler
		// panicHandler     func(interface{}) Handler // Panic recovery handler
		// errorHandler     func(error) Handler       // Error handler

		// Metrics and monitoring
		// metrics  *RouterMetrics  // Router metrics
		// profiler *RouterProfiler // Performance profiler
		// logger   Logger          // Router logger

		// Features
		// cache *RouterCache // Route cache
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

		// paths       *StringMap  // Pre-compiled paths
		maxBodySize int64     // Maximum request body size
		bodyPool    sync.Pool // Body buffer pool
		// routeCache  *RouteCache // Thread-safe route cache
		regexCache map[string]*regexp.Regexp
	}

	// node represents a path segment in the routing tree
	node struct {
		path       string
		children   []*node
		handlers   map[string][]Handler // HTTP method -> handlers
		paramName  string
		isParam    bool
		isWildcard bool
		regex      *regexp.Regexp
		priority   uint32
		mu         sync.RWMutex

		staticChildren []*node // Sorted array for binary search
		paramChildren  []*node // Parameter and regex nodes
		wildcardChild  *node   // Single wildcard child
	}

	// Config holds router configuration
	Config struct {
		MiddlewareTimeout time.Duration
		// ... we'll add configuration options here
	}

	// Metrics tracks router performance
	Metrics struct {
		// ... we'll add metrics here
	}

	// ErrorHandler handles errors during request processing
	// ErrorHandler func(*Context, error)
)

// Router implementation
func NewRouter() *Router {
	r := &Router{
		tree: &node{
			path:     "/",
			handlers: make(map[string][]Handler),
		},
	}

	// Initialize context pool
	r.pool.New = func() interface{} {
		return &Context{
			router: r,
		}
	}

	return r
}

// Add adds a new route with handlers for a specific HTTP method
func (r *Router) Add(method, path string, handlers ...Handler) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(handlers) == 0 {
		panic("router: no handlers provided")
	}

	// Normalize path
	path = r.normalizePath(path)

	// Parse path segments
	segments := r.parsePath(path)
	current := r.tree

	for _, segment := range segments {
		child := current.findChild(segment)
		if child == nil {
			child = current.addChild(segment)
		}
		current = child
	}

	// Add handlers for the method
	current.mu.Lock()
	current.handlers[method] = handlers
	current.mu.Unlock()

	// Update node priority
	atomic.AddUint32(&current.priority, 1)
}

// Helper methods for common HTTP methods
func (r *Router) GET(path string, handlers ...Handler)  { r.Add(http.MethodGet, path, handlers...) }
func (r *Router) POST(path string, handlers ...Handler) { r.Add(http.MethodPost, path, handlers...) }
func (r *Router) PUT(path string, handlers ...Handler)  { r.Add(http.MethodPut, path, handlers...) }
func (r *Router) DELETE(path string, handlers ...Handler) {
	r.Add(http.MethodDelete, path, handlers...)
}
func (r *Router) PATCH(path string, handlers ...Handler) { r.Add(http.MethodPatch, path, handlers...) }

// ServeHTTP implements the http.Handler interface
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// Get context from pool
	ctx := r.pool.Get().(*Context)
	ctx.reset(w, req)
	defer r.pool.Put(ctx)

	// Find route and handle request
	r.handleRequest(ctx)
}

// handleRequest processes the incoming request
func (r *Router) handleRequest(ctx *Context) {
	// Find matching route
	node, params := r.findRoute(ctx.Request.URL.Path)
	if node == nil {
		// r.handleNotFound(ctx)
		return
	}

	// Get handlers for method
	node.mu.RLock()
	handlers, exists := node.handlers[ctx.Request.Method]
	node.mu.RUnlock()

	if !exists {
		// r.handleMethodNotAllowed(ctx)
		return
	}

	// Set route parameters
	for k, v := range params {
		ctx.params.Store(k, v)
	}

	// Set handlers
	ctx.handlers = handlers

	// // Execute middleware chain
	// if !r.executeMiddleware(ctx) {
	// 	return
	// }

	// Execute handlers
	ctx.Next()
}

func (n *node) findChild(segment string) *node {
	n.mu.RLock()
	defer n.mu.RUnlock()

	for _, child := range n.children {
		if child.match(segment) {
			return child
		}
	}
	return nil
}

// func (n *node) addChild(segment string) *node {
// 	child := &node{
// 		path:     segment,
// 		handlers: make(map[string][]Handler),
// 	}

// 	// Check if parameter or wildcard
// 	if strings.HasPrefix(segment, ":") {
// 		child.isParam = true
// 		child.paramName = segment[1:]
// 	} else if segment == "*" {
// 		child.isWildcard = true
// 	}

// 	// Check for regex pattern
// 	if child.isParam && strings.Contains(child.paramName, "(") {
// 		pattern := regexp.MustCompile(`{([^:}]+):([^}]+)}`)
// 		if matches := pattern.FindStringSubmatch(child.paramName); len(matches) == 3 {
// 			child.paramName = matches[1]
// 			child.regex = regexp.MustCompile(matches[2])
// 		}
// 	}

// 	n.mu.Lock()
// 	n.children = append(n.children, child)
// 	n.mu.Unlock()

// 	return child
// }

func (n *node) match(segment string) bool {
	if n.path == segment {
		return true
	}
	if n.isParam {
		if n.regex != nil {
			return n.regex.MatchString(segment)
		}
		return true
	}
	return n.isWildcard
}

// Context implementation
func (c *Context) reset(w http.ResponseWriter, r *http.Request) {
	c.ResponseWriter = w
	c.Request = r
	c.index = -1
	c.aborted.Store(false)
	c.params = sync.Map{}
	c.store = sync.Map{}
	c.errors = c.errors[:0]
	c.start = time.Now()
}

func (c *Context) Next() {
	index := atomic.AddInt32(&c.index, 1)
	for ; index < int32(len(c.handlers)); index++ {
		if c.aborted.Load() {
			return
		}
		c.handlers[index](c)
	}
}

func (c *Context) Abort() {
	c.aborted.Store(true)
}

// Store getters/setters
func (c *Context) Set(key string, value interface{}) {
	c.store.Store(key, value)
}

func (c *Context) Get(key string) (interface{}, bool) {
	return c.store.Load(key)
}

// Error handling
func (c *Context) Error(err error) {
	if c.router.errorHandler != nil {
		c.router.errorHandler(c, err)
	}
}

// Path normalization and parsing
func (r *Router) normalizePath(p string) string {
	// Ensure path starts with /
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}

	// Clean the path
	p = path.Clean(p)

	// Remove trailing slash if not root
	if p != "/" && strings.HasSuffix(p, "/") {
		p = p[:len(p)-1]
	}

	return p
}

func (r *Router) parsePath(path string) []string {
	return strings.Split(strings.Trim(path, "/"), "/")
}

// routeMatch holds the result of route matching
type routeMatch struct {
	node   *node
	params map[string]string
}

// routeCache implements a thread-safe LRU cache for route matching
type routeCache struct {
	cache map[string]routeMatch
	mu    sync.RWMutex
	size  int
}

// findRoute finds the matching route node and extracts URL parameters
func (r *Router) findRoute(path string) (*node, map[string]string) {
	// Check cache first
	if match, ok := r.cache.get(path); ok {
		return match.node, match.params
	}

	// Initialize params map with capacity hint
	params := make(map[string]string, r.maxParams)

	segments := strings.Split(strings.Trim(path, "/"), "/")
	current := r.tree

	// Use string builder for wildcard paths
	var wildcardPath strings.Builder

	for i, segment := range segments {
		// Skip empty segments
		if segment == "" {
			continue
		}

		// Try to find direct child first (most common case)
		child := current.findStaticChild(segment)

		// If no static child found, try parameter and wildcard nodes
		if child == nil {
			child = current.findDynamicChild(segment, params)
		}

		// No matching child found
		if child == nil {
			// Check for catch-all route
			if wildcard := current.findWildcardChild(); wildcard != nil {
				// Build remaining path for wildcard
				wildcardPath.WriteString(strings.Join(segments[i:], "/"))
				params[wildcard.paramName] = wildcardPath.String()

				// Cache the result
				r.cache.set(path, routeMatch{
					node:   wildcard,
					params: params,
				})

				return wildcard, params
			}

			return nil, nil
		}

		current = child
	}

	// Cache the result
	r.cache.set(path, routeMatch{
		node:   current,
		params: params,
	})

	return current, params
}

// findStaticChild finds a static child node matching the segment
func (n *node) findStaticChild(segment string) *node {
	n.mu.RLock()
	defer n.mu.RUnlock()

	// Binary search for static nodes (they're kept sorted)
	left, right := 0, len(n.staticChildren)-1
	for left <= right {
		mid := (left + right) / 2
		child := n.staticChildren[mid]

		if child.path == segment {
			return child
		}

		if child.path < segment {
			left = mid + 1
		} else {
			right = mid - 1
		}
	}

	return nil
}

// findDynamicChild finds a parameter or regex node matching the segment
func (n *node) findDynamicChild(segment string, params map[string]string) *node {
	n.mu.RLock()
	defer n.mu.RUnlock()

	// Check parameter nodes
	for _, child := range n.paramChildren {
		if child.regex != nil {
			// Check regex match
			if child.regex.MatchString(segment) {
				params[child.paramName] = segment
				return child
			}
		} else {
			// Regular parameter node
			params[child.paramName] = segment
			return child
		}
	}

	return nil
}

// findWildcardChild finds a wildcard (catch-all) child node
func (n *node) findWildcardChild() *node {
	n.mu.RLock()
	defer n.mu.RUnlock()

	if n.wildcardChild != nil {
		return n.wildcardChild
	}
	return nil
}

// addChild adds a new child node with proper categorization
func (n *node) addChild(segment string) *node {
	n.mu.Lock()
	defer n.mu.Unlock()

	child := &node{
		path:     segment,
		handlers: make(map[string][]Handler),
	}

	// Categorize the node
	if strings.HasPrefix(segment, ":") {
		// Parameter node
		paramName := segment[1:]

		// Check for regex pattern
		if idx := strings.Index(paramName, "("); idx != -1 {
			pattern := paramName[idx+1 : len(paramName)-1]
			child.paramName = paramName[:idx]
			child.regex = regexp.MustCompile("^" + pattern + "$")
		} else {
			child.paramName = paramName
		}

		n.paramChildren = append(n.paramChildren, child)
	} else if segment == "*" {
		// Wildcard node
		n.wildcardChild = child
	} else {
		// Static node - maintain sorted order
		n.staticChildren = insertSorted(n.staticChildren, child)
	}

	return child
}

// insertSorted inserts a node into a sorted array of nodes
func insertSorted(nodes []*node, node *node) []*node {
	i := sort.Search(len(nodes), func(i int) bool {
		return nodes[i].path >= node.path
	})

	nodes = append(nodes, nil)
	copy(nodes[i+1:], nodes[i:])
	nodes[i] = node

	return nodes
}

// Route cache implementation
func newRouteCache(size int) *routeCache {
	return &routeCache{
		cache: make(map[string]routeMatch, size),
		size:  size,
	}
}

func (rc *routeCache) get(path string) (routeMatch, bool) {
	rc.mu.RLock()
	match, ok := rc.cache[path]
	rc.mu.RUnlock()
	return match, ok
}

func (rc *routeCache) set(path string, match routeMatch) {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	// Simple eviction strategy: remove random entry if cache is full
	if len(rc.cache) >= rc.size {
		// Delete a random entry
		for k := range rc.cache {
			delete(rc.cache, k)
			break
		}
	}

	rc.cache[path] = match
}

// Optimization: Pre-compile common regex patterns
var (
	intRegex  = regexp.MustCompile(`^\d+$`)
	uuidRegex = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)
	slugRegex = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
)

// Helper methods for common parameter patterns
func (r *Router) IntParam(name string) string {
	return fmt.Sprintf(":%s(%s)", name, intRegex.String())
}

func (r *Router) UUIDParam(name string) string {
	return fmt.Sprintf(":%s(%s)", name, uuidRegex.String())
}

func (r *Router) SlugParam(name string) string {
	return fmt.Sprintf(":%s(%s)", name, slugRegex.String())
}

type (

	// MiddlewareFunc defines the middleware handler function
	MiddlewareFunc func(*Context) bool

	// // MiddlewareChain represents a chain of middleware
	MiddlewareChain struct {
		middlewares []MiddlewareFunc
		mu          sync.RWMutex
	}

	// MiddlewareConfig holds configuration for middleware
	MiddlewareConfig struct {
		Priority   int           // Execution priority (lower runs first)
		Timeout    time.Duration // Maximum execution time
		Required   bool          // If true, request fails if middleware fails
		SkipPaths  []string      // Paths to skip this middleware
		OnlyPaths  []string      // Only run on these paths
		Conditions []Condition   // Additional conditions for execution
	}

	// Condition defines when middleware should run
	Condition func(*Context) bool
)

// Middleware implementation for Router
func (r *Router) Use(middleware ...MiddlewareFunc) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.middleware = append(r.middleware, middleware...)
}

// Group-level middleware
func (g *RouterGroup) Use(middleware ...MiddlewareFunc) *RouterGroup {
	g.middleware = append(g.middleware, middleware...)
	return g
}

// Execute middleware chain
func (r *Router) executeMiddleware(c *Context) bool {
	// Combined middleware (global + group + route)
	middleware := r.combineMiddleware(c)

	for _, m := range middleware {
		// Check if request was aborted
		if c.aborted.Load() {
			return false
		}

		// Execute middleware with timeout and recovery
		if docontinue := r.executeMiddlewareFunc(c, m); !docontinue {
			return false
		}
	}

	return true
}

// Middleware execution with timeout and recovery
func (r *Router) executeMiddlewareFunc(c *Context, m MiddlewareFunc) bool {
	var err error
	var docontinue bool
	done := make(chan struct{})

	// Create timeout context if configured
	ctx := c.Request.Context()
	if timeout := r.config.MiddlewareTimeout; timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	// Execute middleware in goroutine
	go func() {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("middleware panic: %v", r)
			}
			close(done)
		}()

		docontinue = m(c)
	}()

	// Wait for completion or timeout
	select {
	case <-done:
		return docontinue
	case <-ctx.Done():
		return fmt.Errorf("middleware timeout: %v", ctx.Err())
	}
}

// Common middleware implementations
type commonMiddleware struct {
	config MiddlewareConfig
}

// Logger middleware
func Logger(config ...MiddlewareConfig) MiddlewareFunc {
	cfg := defaultMiddlewareConfig
	if len(config) > 0 {
		cfg = config[0]
	}

	return func(c *Context) error {
		start := time.Now()

		// Store start time for other middleware
		c.Set("request_start_time", start)

		// Process request
		c.Next()

		// Calculate duration
		duration := time.Since(start)

		// Log request details
		fmt.Printf("[%s] %s %s %v\n",
			time.Now().Format(time.RFC3339),
			c.Request.Method,
			c.Request.URL.Path,
			duration,
		)

		return nil
	}
}

// Recovery middleware
func Recovery(config ...MiddlewareConfig) MiddlewareFunc {
	return func(c *Context) error {
		defer func() {
			if err := recover(); err != nil {
				// Log stack trace
				stack := debug.Stack()

				// Create error response
				httpError := NewHTTPError(
					http.StatusInternalServerError,
					fmt.Sprintf("panic recovered: %v", err),
				)
				httpError.Stack = string(stack)

				// Handle error
				c.Error(httpError)
				c.Abort()
			}
		}()

		return nil
	}
}

// CORS middleware
func CORS(config CORSConfig) MiddlewareFunc {
	return func(c *Context) error {
		// Set CORS headers
		headers := c.ResponseWriter.Header()

		// Handle preflight requests
		if c.Request.Method == http.MethodOptions {
			headers.Set("Access-Control-Allow-Methods", strings.Join(config.AllowMethods, ","))
			headers.Set("Access-Control-Allow-Headers", strings.Join(config.AllowHeaders, ","))
			headers.Set("Access-Control-Max-Age", strconv.Itoa(config.MaxAge))
			c.ResponseWriter.WriteHeader(http.StatusNoContent)
			return nil
		}

		// Set allowed origins
		origin := c.Request.Header.Get("Origin")
		if config.AllowAllOrigins {
			headers.Set("Access-Control-Allow-Origin", "*")
		} else if isAllowedOrigin(origin, config.AllowOrigins) {
			headers.Set("Access-Control-Allow-Origin", origin)
		}

		// Set other CORS headers
		if config.AllowCredentials {
			headers.Set("Access-Control-Allow-Credentials", "true")
		}

		if len(config.ExposeHeaders) > 0 {
			headers.Set("Access-Control-Expose-Headers", strings.Join(config.ExposeHeaders, ","))
		}

		return nil
	}
}

// RateLimit middleware
func RateLimit(config RateLimitConfig) MiddlewareFunc {
	limiter := newRateLimiter(config)

	return func(c *Context) error {
		// Get client identifier
		identifier := config.KeyFunc(c)

		// Check rate limit
		if !limiter.Allow(identifier) {
			return NewHTTPError(
				http.StatusTooManyRequests,
				"rate limit exceeded",
			)
		}

		return nil
	}
}

// Auth middleware
func Auth(config AuthConfig) MiddlewareFunc {
	return func(c *Context) error {
		// Get token from header or query
		token := c.GetToken()

		// Validate token
		claims, err := validateToken(token, config)
		if err != nil {
			return NewHTTPError(
				http.StatusUnauthorized,
				"invalid token",
			)
		}

		// Store claims in context
		c.Set("claims", claims)

		return nil
	}
}

// Timeout middleware
func Timeout(timeout time.Duration) MiddlewareFunc {
	return func(c *Context) error {
		// Create timeout context
		ctx, cancel := context.WithTimeout(c.Request.Context(), timeout)
		defer cancel()

		// Replace request context
		c.Request = c.Request.WithContext(ctx)

		// Create done channel
		done := make(chan struct{})

		go func() {
			c.Next()
			close(done)
		}()

		select {
		case <-done:
			return nil
		case <-ctx.Done():
			return NewHTTPError(
				http.StatusGatewayTimeout,
				"request timeout",
			)
		}
	}
}

// Compression middleware
func Compression(config CompressionConfig) MiddlewareFunc {
	pool := newCompressorPool(config)

	return func(c *Context) error {
		// Check if compression should be skipped
		if shouldSkipCompression(c, config) {
			return nil
		}

		// Get compressor
		compressor := pool.get(c.Request)
		if compressor == nil {
			return nil
		}
		defer pool.put(compressor)

		// Wrap response writer
		c.ResponseWriter = newCompressResponseWriter(
			c.ResponseWriter,
			compressor,
			config,
		)

		return nil
	}
}

// Helper functions
func shouldSkipCompression(c *Context, config CompressionConfig) bool {
	// Check content type
	contentType := c.GetHeader("Content-Type")
	if !isCompressibleType(contentType, config.Types) {
		return true
	}

	// Check path
	path := c.Request.URL.Path
	for _, skip := range config.SkipPaths {
		if strings.HasPrefix(path, skip) {
			return true
		}
	}

	return false
}

// Middleware chain management
func (r *Router) Group(prefix string, middleware ...MiddlewareFunc) *RouterGroup {
	return &RouterGroup{
		prefix:     prefix,
		router:     r,
		middleware: middleware,
	}
}

// Combine middleware from router, group, and route
func (r *Router) combineMiddleware(c *Context) []MiddlewareFunc {
	var middleware []MiddlewareFunc

	// Add global middleware
	middleware = append(middleware, r.middleware...)

	// Add group middleware
	if group, ok := c.Get("group").(*RouterGroup); ok {
		middleware = append(middleware, group.middleware...)
	}

	// Add route-specific middleware
	if routeMiddleware, ok := c.Get("route_middleware").([]MiddlewareFunc); ok {
		middleware = append(middleware, routeMiddleware...)
	}

	return middleware
}

// Route represents a route group
type Route struct {
	prefix     string
	router     *Router
	middleware []MiddlewareFunc
	parent     *Route // Added to support nested groups
}

// Add adds a route to the group with middleware chain
func (g *Route) Add(method, path string, handlers ...Handler) {
	if len(handlers) == 0 {
		panic("router: no handlers provided")
	}

	// Build full path including all parent prefixes
	fullPath := g.buildFullPath(path)

	// Combine all middleware (parent groups + current group + route specific)
	allMiddleware := g.gatherMiddleware()

	// Create final handlers slice with capacity for all handlers
	finalHandlers := make([]Handler, 0, len(allMiddleware)+len(handlers))

	// Add middleware handlers first
	for _, mw := range allMiddleware {
		// Convert middleware to handler
		handler := createMiddlewareHandler(mw)
		finalHandlers = append(finalHandlers, handler)
	}

	// Add route handlers
	finalHandlers = append(finalHandlers, handlers...)

	// Add route to router
	g.router.Add(method, fullPath, finalHandlers...)
}

// Helper methods

// buildFullPath constructs the full path including all parent prefixes
func (g *Route) buildFullPath(path string) string {
	// Gather all prefixes from parent groups
	var prefixes []string
	current := g
	for current != nil {
		if current.prefix != "" {
			prefixes = append(prefixes, current.prefix)
		}
		current = current.parent
	}

	// Build full path in reverse order
	var fullPath strings.Builder
	for i := len(prefixes) - 1; i >= 0; i-- {
		prefix := prefixes[i]
		fullPath.WriteString(prefix)
		// Ensure single slash between segments
		if !strings.HasSuffix(prefix, "/") && !strings.HasPrefix(path, "/") {
			fullPath.WriteString("/")
		}
	}
	fullPath.WriteString(path)

	return fullPath.String()
}

// gatherMiddleware collects middleware from all parent groups
func (g *Route) gatherMiddleware() []MiddlewareFunc {
	// Count total middleware for capacity hint
	count := 0
	current := g
	for current != nil {
		count += len(current.middleware)
		current = current.parent
	}

	// Gather middleware in correct order (parent -> child)
	middleware := make([]MiddlewareFunc, 0, count)
	var gather func(*Route)
	gather = func(r *Route) {
		if r.parent != nil {
			gather(r.parent)
		}
		middleware = append(middleware, r.middleware...)
	}
	gather(g)

	return middleware
}

// createMiddlewareHandler converts a MiddlewareFunc to a Handler
func createMiddlewareHandler(mw MiddlewareFunc) Handler {
	return func(c *Context) {
		if err := mw(c); err != nil {
			c.Error(err)
			c.Abort()
			return
		}
		c.Next()
	}
}

// Convenience methods for HTTP verbs
func (g *Route) GET(path string, handlers ...Handler) {
	g.Add(http.MethodGet, path, handlers...)
}

func (g *Route) POST(path string, handlers ...Handler) {
	g.Add(http.MethodPost, path, handlers...)
}

func (g *Route) PUT(path string, handlers ...Handler) {
	g.Add(http.MethodPut, path, handlers...)
}

func (g *Route) DELETE(path string, handlers ...Handler) {
	g.Add(http.MethodDelete, path, handlers...)
}

func (g *Route) PATCH(path string, handlers ...Handler) {
	g.Add(http.MethodPatch, path, handlers...)
}

// Group creates a new sub-group
func (g *Route) Group(prefix string, middleware ...MiddlewareFunc) *Route {
	return &Route{
		prefix:     prefix,
		router:     g.router,
		middleware: middleware,
		parent:     g,
	}
}

// Use adds middleware to the group
func (g *Route) Use(middleware ...MiddlewareFunc) *Route {
	g.middleware = append(g.middleware, middleware...)
	return g
}

// RouterGroup defines a logical grouping of routes with shared middleware and configuration
type RouterGroup struct {
	prefix     string
	router     *Router
	parent     *RouterGroup
	middleware []MiddlewareFunc

	// Group-specific configuration
	config struct {
		noSlash       bool // Don't append trailing slash
		caseSensitive bool // Case-sensitive routing
		middleware    []MiddlewareFunc
	}
}

// Group creates a new router group
func (r *Router) Group(prefix string, middleware ...MiddlewareFunc) *RouterGroup {
	return &RouterGroup{
		prefix:     prefix,
		router:     r,
		middleware: middleware,
	}
}

// Group creates a sub-group
func (g *RouterGroup) Group(prefix string, middleware ...MiddlewareFunc) *RouterGroup {
	return &RouterGroup{
		prefix:     g.calculatePrefix(prefix),
		router:     g.router,
		parent:     g,
		middleware: middleware,
	}
}

// Route handlers for RouterGroup
func (g *RouterGroup) GET(path string, handlers ...Handler) {
	g.handle(http.MethodGet, path, handlers)
}

func (g *RouterGroup) POST(path string, handlers ...Handler) {
	g.handle(http.MethodPost, path, handlers)
}

func (g *RouterGroup) PUT(path string, handlers ...Handler) {
	g.handle(http.MethodPut, path, handlers)
}

func (g *RouterGroup) DELETE(path string, handlers ...Handler) {
	g.handle(http.MethodDelete, path, handlers)
}

func (g *RouterGroup) PATCH(path string, handlers ...Handler) {
	g.handle(http.MethodPatch, path, handlers)
}

func (g *RouterGroup) HEAD(path string, handlers ...Handler) {
	g.handle(http.MethodHead, path, handlers)
}

func (g *RouterGroup) OPTIONS(path string, handlers ...Handler) {
	g.handle(http.MethodOptions, path, handlers)
}

// handle registers a new request handle and middleware with the given path and method
func (g *RouterGroup) handle(method, path string, handlers []Handler) {
	fullPath := g.calculatePrefix(path)

	// Combine middleware
	finalHandlers := g.combineHandlers(handlers)

	// Add route to router
	g.router.Add(method, fullPath, finalHandlers...)
}

// Use adds middleware to the group
func (g *RouterGroup) Use(middleware ...MiddlewareFunc) *RouterGroup {
	g.middleware = append(g.middleware, middleware...)
	return g
}

// Internal helper methods

// calculatePrefix builds the full prefix for the group
func (g *RouterGroup) calculatePrefix(relativePath string) string {
	if relativePath == "" {
		return g.prefix
	}

	finalPath := path.Join(g.prefix, relativePath)
	if !g.config.noSlash && g.prefix[len(g.prefix)-1] == '/' && relativePath[0] != '/' {
		return finalPath + "/"
	}
	return finalPath
}

// combineHandlers combines group middleware with route handlers
func (g *RouterGroup) combineHandlers(handlers []Handler) []Handler {
	// Calculate total middleware count
	totalSize := len(g.middleware)
	if g.parent != nil {
		parentMiddleware := g.getAllParentMiddleware()
		totalSize += len(parentMiddleware)
	}
	totalSize += len(handlers)

	// Create final handlers slice
	finalHandlers := make([]Handler, 0, totalSize)

	// Add parent middleware
	if g.parent != nil {
		finalHandlers = append(finalHandlers, g.convertMiddleware(g.getAllParentMiddleware())...)
	}

	// Add group middleware
	finalHandlers = append(finalHandlers, g.convertMiddleware(g.middleware)...)

	// Add route handlers
	finalHandlers = append(finalHandlers, handlers...)

	return finalHandlers
}

// getAllParentMiddleware collects middleware from all parent groups
func (g *RouterGroup) getAllParentMiddleware() []MiddlewareFunc {
	var middleware []MiddlewareFunc
	parent := g.parent

	// Traverse up the group hierarchy
	for parent != nil {
		// Prepend parent middleware (to maintain correct order)
		middleware = append(parent.middleware, middleware...)
		parent = parent.parent
	}

	return middleware
}

// convertMiddleware converts MiddlewareFunc to Handler
func (g *RouterGroup) convertMiddleware(middleware []MiddlewareFunc) []Handler {
	handlers := make([]Handler, len(middleware))
	for i, mw := range middleware {
		mwCopy := mw // Create a copy to avoid closure problems
		handlers[i] = func(c *Context) {
			if err := mwCopy(c); err != nil {
				c.Error(err)
				c.Abort()
				return
			}
			c.Next()
		}
	}
	return handlers
}

// Configuration methods

// CaseSensitive enables case-sensitive routing
func (g *RouterGroup) CaseSensitive(value bool) *RouterGroup {
	g.config.caseSensitive = value
	return g
}

// NoSlash disables automatic trailing slash handling
func (g *RouterGroup) NoSlash(value bool) *RouterGroup {
	g.config.noSlash = value
	return g
}

// Static serves files from the given file system root
func (g *RouterGroup) Static(relativePath, root string) {
	handler := g.createStaticHandler(root)
	urlPattern := path.Join(relativePath, "/*filepath")
	g.GET(urlPattern, handler)
}

// StaticFS works like Static but with custom http.FileSystem
func (g *RouterGroup) StaticFS(relativePath string, fs http.FileSystem) {
	handler := g.createStaticFSHandler(fs)
	urlPattern := path.Join(relativePath, "/*filepath")
	g.GET(urlPattern, handler)
}

// Helper methods for static file serving
func (g *RouterGroup) createStaticHandler(root string) Handler {
	return func(c *Context) {
		filepath := c.Param("filepath")
		if filepath == "" {
			filepath = "index.html"
		}
		c.File(path.Join(root, filepath))
	}
}

func (g *RouterGroup) createStaticFSHandler(fs http.FileSystem) Handler {
	fileServer := http.FileServer(fs)
	return func(c *Context) {
		filepath := c.Param("filepath")
		c.Request.URL.Path = filepath
		fileServer.ServeHTTP(c.ResponseWriter, c.Request)
	}
}

// Router integration
func (r *Router) Static(prefix, root string, config ...FileServerConfig) {
	cfg := DefaultFileServerConfig
	if len(config) > 0 {
		cfg = config[0]
	}
	cfg.Root = root

	fs := NewFileServer(cfg)
	r.Get(prefix+"/*path", func(c *Context) {
		fs.ServeHTTP(c.ResponseWriter, c.Request)
	})
}

type (
	// FileServer configuration
	FileServerConfig struct {
		Root            string            // Root directory for static files
		Index           string            // Index file (e.g., "index.html")
		MaxAge          time.Duration     // Cache control max age
		Compress        bool              // Enable compression
		CompressMinSize int64             // Minimum size for compression
		EtagEnabled     bool              // Enable ETag support
		DirList         bool              // Enable directory listing
		CustomHeaders   map[string]string // Custom headers for static files
		AllowedExt      []string          // Allowed file extensions
		Cache           FileCache         // File cache implementation
		ErrorHandler    ErrorHandler      // Custom error handler
	}

	// FileCache interface for caching static files
	FileCache interface {
		Get(path string) (*CachedFile, bool)
		Set(path string, file *CachedFile)
		Remove(path string)
		Clear()
	}

	// CachedFile represents a cached static file
	CachedFile struct {
		Data       []byte
		ETag       string
		ModTime    time.Time
		Size       int64
		MimeType   string
		Compressed []byte
	}

	// // FileServer handles static file serving
	// FileServer struct {
	// 	config FileServerConfig
	// 	cache  FileCache
	// 	pool   *sync.Pool // Compression buffer pool
	// }

	// MemoryFileCache implements in-memory file caching
	MemoryFileCache struct {
		files map[string]*CachedFile
		mu    sync.RWMutex
	}
)

// Default configuration
var DefaultFileServerConfig = FileServerConfig{
	Index:           "index.html",
	MaxAge:          24 * time.Hour,
	Compress:        true,
	CompressMinSize: 1024, // 1KB
	EtagEnabled:     true,
	DirList:         false,
	CustomHeaders: map[string]string{
		"X-Content-Type-Options": "nosniff",
	},
	AllowedExt: []string{
		".css", ".js", ".html", ".htm", ".png", ".jpg", ".jpeg",
		".gif", ".svg", ".woff", ".woff2", ".ttf", ".eot",
	},
}

// Create new file server
func NewFileServer(config FileServerConfig) *FileServer {
	if config.Cache == nil {
		config.Cache = NewMemoryFileCache()
	}

	fs := &FileServer{
		config: config,
		cache:  config.Cache,
		pool: &sync.Pool{
			New: func() interface{} {
				return make([]byte, 32*1024) // 32KB buffer
			},
		},
	}

	return fs
}

// ServeHTTP implements http.Handler
func (fs *FileServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Clean and validate path
	urlPath := path.Clean(r.URL.Path)
	if !fs.validatePath(urlPath) {
		fs.handleError(w, r, http.StatusForbidden, "Forbidden")
		return
	}

	// Check cache
	if cached, ok := fs.cache.Get(urlPath); ok {
		fs.serveFromCache(w, r, cached)
		return
	}

	// Get file info
	filePath := filepath.Join(fs.config.Root, urlPath)
	info, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			fs.handleError(w, r, http.StatusNotFound, "Not Found")
		} else {
			fs.handleError(w, r, http.StatusInternalServerError, "Internal Server Error")
		}
		return
	}

	// Handle directory
	if info.IsDir() {
		fs.handleDirectory(w, r, filePath, urlPath)
		return
	}

	// Serve file
	fs.serveFile(w, r, filePath, info)
}

// Cache implementation
func NewMemoryFileCache() *MemoryFileCache {
	return &MemoryFileCache{
		files: make(map[string]*CachedFile),
	}
}

func (c *MemoryFileCache) Get(path string) (*CachedFile, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	file, ok := c.files[path]
	return file, ok
}

func (c *MemoryFileCache) Set(path string, file *CachedFile) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.files[path] = file
}

// Helper methods
func (fs *FileServer) validatePath(urlPath string) bool {
	if strings.Contains(urlPath, "..") {
		return false
	}

	if !fs.config.DirList && strings.HasSuffix(urlPath, "/") {
		return false
	}

	ext := filepath.Ext(urlPath)
	if ext != "" {
		allowed := false
		for _, allowedExt := range fs.config.AllowedExt {
			if ext == allowedExt {
				allowed = true
				break
			}
		}
		if !allowed {
			return false
		}
	}

	return true
}

func (fs *FileServer) serveFromCache(w http.ResponseWriter, r *http.Request, cached *CachedFile) {
	// Check if-none-match
	if fs.config.EtagEnabled {
		if etag := r.Header.Get("If-None-Match"); etag == cached.ETag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", cached.ETag)
	}

	// Set headers
	w.Header().Set("Content-Type", cached.MimeType)
	w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", int(fs.config.MaxAge.Seconds())))

	for k, v := range fs.config.CustomHeaders {
		w.Header().Set(k, v)
	}

	// Check if we can serve compressed version
	if fs.config.Compress && cached.Compressed != nil &&
		strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		w.Header().Set("Content-Encoding", "gzip")
		w.Write(cached.Compressed)
		return
	}

	w.Write(cached.Data)
}

func (fs *FileServer) serveFile(w http.ResponseWriter, r *http.Request, filePath string, info os.FileInfo) {
	// Read file
	data, err := os.ReadFile(filePath)
	if err != nil {
		// fs.handleError(w, r, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	// Create cached file
	cached := &CachedFile{
		Data:     data,
		ModTime:  info.ModTime(),
		Size:     info.Size(),
		MimeType: mime.TypeByExtension(filepath.Ext(filePath)),
	}

	// Generate ETag
	if fs.config.EtagEnabled {
		hash := sha256.Sum256(data)
		cached.ETag = fmt.Sprintf(`"%x"`, hash[:16])
	}

	// Compress if needed
	if fs.config.Compress && info.Size() >= fs.config.CompressMinSize {
		cached.Compressed = fs.compress(data)
	}

	// Cache file
	fs.cache.Set(r.URL.Path, cached)

	// Serve file
	fs.serveFromCache(w, r, cached)
}

func (fs *FileServer) compress(data []byte) []byte {
	buf := new(strings.Builder)
	gz := gzip.NewWriter(buf)
	if _, err := gz.Write(data); err != nil {
		return nil
	}
	if err := gz.Close(); err != nil {
		return nil
	}
	return []byte(buf.String())
}

func (fs *FileServer) handleDirectory(w http.ResponseWriter, r *http.Request, dirPath, urlPath string) {
	// Check for index file
	if fs.config.Index != "" {
		indexPath := filepath.Join(dirPath, fs.config.Index)
		if info, err := os.Stat(indexPath); err == nil && !info.IsDir() {
			fs.serveFile(w, r, indexPath, info)
			return
		}
	}

	// Directory listing
	if !fs.config.DirList {
		// fs.handleError(w, r, http.StatusForbidden, "Directory listing not allowed")
		return
	}

	entries, err := os.ReadDir(dirPath)
	if err != nil {
		// fs.handleError(w, r, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<pre>\n")
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() {
			name += "/"
		}
		fmt.Fprintf(w, "<a href=\"%s\">%s</a>\n", path.Join(urlPath, name), name)
	}
	fmt.Fprintf(w, "</pre>\n")
}

type HTTPError struct {
	Code    int
	Message string
	Err     error // Original error
}

// Error implements the error interface
func (e *HTTPError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("HTTP %d: %s: %v", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("HTTP %d: %s", e.Code, e.Message)
}

// handleError processes an error through the appropriate handler
func (r *Router) handleError(ctx *Context, err error) {
	if err == nil {
		return
	}

	var httpError *HTTPError
	if e, ok := err.(*HTTPError); ok {
		httpError = e
	} else {
		// Convert regular error to HTTPError
		httpError = &HTTPError{
			Code:    http.StatusInternalServerError,
			Message: err.Error(),
			Err:     err,
		}
	}

	// Find appropriate handler
	if handler, ok := r.errorHandlers[httpError.Code]; ok {
		handler(ctx, httpError)
		return
	}

	// Fall back to global error handler
	if r.errorHandler != nil {
		r.errorHandler(ctx, httpError)
		return
	}

	// Default error response
	http.Error(ctx.ResponseWriter, httpError.Message, httpError.Code)
}

// FileServer represents a file serving handler
type FileServer struct {
	root           http.FileSystem
	indices        bool
	errorHandler   ErrorHandler
	pathRewriter   PathRewriter
	contentHandler ContentHandler
	maxAge         int // Cache control max-age in seconds
}

type (
	// ErrorHandler handles file serving errors
	ErrorHandler func(*Context, error)

	// PathRewriter can rewrite file paths before serving
	PathRewriter func(string) string

	// ContentHandler processes file content before serving
	ContentHandler func(*Context, http.File) error
)

// NewFileServer creates a new file server instance
func NewFileServer(root http.FileSystem, options ...FileServerOption) *FileServer {
	fs := &FileServer{
		root:    root,
		indices: true,
		maxAge:  86400, // 1 day default
	}

	// Apply options
	for _, opt := range options {
		opt(fs)
	}

	// Set default error handler if none provided
	if fs.errorHandler == nil {
		fs.errorHandler = fs.defaultErrorHandler
	}

	return fs
}

// handleError processes file serving errors
func (fs *FileServer) handleError(c *Context, err error) {
	if fs.errorHandler != nil {
		fs.errorHandler(c, err)
		return
	}

	// Default error handling
	switch {
	case errors.Is(err, os.ErrNotExist):
		c.Status(http.StatusNotFound)

	case errors.Is(err, os.ErrPermission):
		c.Status(http.StatusForbidden)

	default:
		c.Status(http.StatusInternalServerError)
	}
}

// ServeHTTP implements http.Handler
func (fs *FileServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Create context for this request
	c := &Context{
		Request:        r,
		ResponseWriter: w,
	}

	// Clean path
	urlPath := r.URL.Path
	if !strings.HasPrefix(urlPath, "/") {
		urlPath = "/" + urlPath
		r.URL.Path = urlPath
	}

	// Apply path rewriter if configured
	if fs.pathRewriter != nil {
		urlPath = fs.pathRewriter(urlPath)
	}

	// Try to open the file
	f, err := fs.root.Open(urlPath)
	if err != nil {
		fs.handleError(c, err)
		return
	}
	defer f.Close()

	// Get file info
	stat, err := f.Stat()
	if err != nil {
		fs.handleError(c, err)
		return
	}

	// Handle directory
	if stat.IsDir() {
		if !fs.indices {
			fs.handleError(c, os.ErrPermission)
			return
		}

		// Redirect if missing trailing slash
		if !strings.HasSuffix(r.URL.Path, "/") {
			localRedirect(w, r, path.Base(r.URL.Path)+"/")
			return
		}

		// Try to serve index.html
		index := filepath.Join(urlPath, "index.html")
		if indexFile, err := fs.root.Open(index); err == nil {
			defer indexFile.Close()
			if indexStat, err := indexFile.Stat(); err == nil {
				f = indexFile
				stat = indexStat
			}
		}
	}

	// Set cache control headers
	if fs.maxAge > 0 {
		w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", fs.maxAge))
	}

	// Set content type
	contentType := mime.TypeByExtension(filepath.Ext(urlPath))
	if contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}

	// Set content length
	w.Header().Set("Content-Length", strconv.FormatInt(stat.Size(), 10))

	// Handle custom content processing
	if fs.contentHandler != nil {
		if err := fs.contentHandler(c, f); err != nil {
			fs.handleError(c, err)
			return
		}
		return
	}

	// Serve the file
	http.ServeContent(w, r, stat.Name(), stat.ModTime(), f)
}

// Default error handler
func (fs *FileServer) defaultErrorHandler(c *Context, err error) {
	switch {
	case errors.Is(err, os.ErrNotExist):
		c.JSON(http.StatusNotFound, map[string]string{
			"error": "File not found",
		})

	case errors.Is(err, os.ErrPermission):
		c.JSON(http.StatusForbidden, map[string]string{
			"error": "Permission denied",
		})

	default:
		c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Internal server error",
		})
	}
}

// FileServer options
type FileServerOption func(*FileServer)

func WithIndices(enable bool) FileServerOption {
	return func(fs *FileServer) {
		fs.indices = enable
	}
}

func WithErrorHandler(handler ErrorHandler) FileServerOption {
	return func(fs *FileServer) {
		fs.errorHandler = handler
	}
}

func WithPathRewriter(rewriter PathRewriter) FileServerOption {
	return func(fs *FileServer) {
		fs.pathRewriter = rewriter
	}
}

func WithContentHandler(handler ContentHandler) FileServerOption {
	return func(fs *FileServer) {
		fs.contentHandler = handler
	}
}

func WithMaxAge(seconds int) FileServerOption {
	return func(fs *FileServer) {
		fs.maxAge = seconds
	}
}

// Helper functions

// localRedirect gives a Moved Permanently response.
func localRedirect(w http.ResponseWriter, r *http.Request, newPath string) {
	if q := r.URL.RawQuery; q != "" {
		newPath += "?" + q
	}
	w.Header().Set("Location", newPath)
	w.WriteHeader(http.StatusMovedPermanently)
}

// Reset resets the context for reuse
func (c *Context) Reset(w http.ResponseWriter, r *http.Request) {
	c.Request = r
	c.ResponseWriter = w
	c.queryParsed = false
	c.headersParsed = false
	c.start = time.Now()
	c.router = nil
	c.params.Reset()

}

// Param gets a URL parameter value
func (c *Context) Param(name string) string {
	return c.params.Get(name)
}

// Param gets a URL parameter value
func (c *Context) Took() string {
	return time.Since(c.start).String()
}

// Query gets a query parameter value (lazy parsing)
func (c *Context) Query(name string) string {
	if !c.queryParsed {
		c.query = c.Request.URL.Query()
		c.queryParsed = true
	}

	if values, ok := c.query[name]; ok && len(values) > 0 {
		return values[0]
	}
	return ""
}

// Header gets a header value (lazy parsing)
func (c *Context) Header(name string) string {
	if !c.headersParsed {
		c.headers = c.Request.Header
		c.headersParsed = true
	}
	if values, ok := c.headers[name]; ok && len(values) > 0 {
		return values[0]
	}
	return ""
}

// Body reads the request body
func (c *Context) Body() ([]byte, error) {
	return io.ReadAll(c.Request.Body)
}

// Body parsing methods for Context
func (c *Context) BindJSON(v interface{}) error {
	if !c.bodyParsed {
		if c.Request.Body == nil {
			return fmt.Errorf("empty body")
		}

		// Use body pool
		buf := c.router.bodyPool.Get().([]byte)
		defer c.router.bodyPool.Put(buf)

		// Limit body size
		r := io.LimitReader(c.Request.Body, c.router.maxBodySize)
		if _, err := r.Read(buf); err != nil && err != io.EOF {
			return err
		}

		if err := json.Unmarshal(buf, v); err != nil {
			return err
		}
		c.bodyParsed = true
	}
	return nil
}

// Form parsing methods
func (c *Context) FormValue(key string) string {
	if !c.bodyParsed {
		c.Request.ParseForm()
		c.formData = c.Request.Form
		c.bodyParsed = true
	}
	return c.formData.Get(key)
}

func (c *Context) FormInt(key string) (int, error) {
	return strconv.Atoi(c.FormValue(key))
}

func (c *Context) FormInt64(key string) (int64, error) {
	return strconv.ParseInt(c.FormValue(key), 10, 64)
}

func (c *Context) FormFloat64(key string) (float64, error) {
	return strconv.ParseFloat(c.FormValue(key), 64)
}

func (c *Context) FormBool(key string) (bool, error) {
	return strconv.ParseBool(c.FormValue(key))
}

func (c *Context) FormTime(key, layout string) (time.Time, error) {
	return time.Parse(layout, c.FormValue(key))
}

// Query string parsing methods
func (c *Context) QueryInt(key string, defaultVal int) int {
	if val, err := strconv.Atoi(c.Query(key)); err == nil {
		return val
	}
	return defaultVal
}

func (c *Context) QueryInt64(key string, defaultVal int64) int64 {
	if val, err := strconv.ParseInt(c.Query(key), 10, 64); err == nil {
		return val
	}
	return defaultVal
}

func (c *Context) QueryFloat64(key string, defaultVal float64) float64 {
	if val, err := strconv.ParseFloat(c.Query(key), 64); err == nil {
		return val
	}
	return defaultVal
}

func (c *Context) QueryBool(key string, defaultVal bool) bool {
	if val, err := strconv.ParseBool(c.Query(key)); err == nil {
		return val
	}
	return defaultVal
}

func (c *Context) QueryTime(key, layout string, defaultVal time.Time) time.Time {
	if val, err := time.Parse(layout, c.Query(key)); err == nil {
		return val
	}
	return defaultVal
}

func (c *Context) QueryDuration(key string, defaultVal time.Duration) time.Duration {
	if val, err := time.ParseDuration(c.Query(key)); err == nil {
		return val
	}
	return defaultVal
}

// File handling methods
func (c *Context) FormFile(key string) (*multipart.FileHeader, error) {
	if c.multipartForm == nil {
		if err := c.Request.ParseMultipartForm(c.maxMemory); err != nil {
			return nil, err
		}
		c.multipartForm = c.Request.MultipartForm
	}
	file, header, err := c.Request.FormFile(key)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return header, nil
}

// Response helpers
func (c *Context) JSON(code int, v interface{}) error {
	c.ResponseWriter.Header().Set("Content-Type", "application/json")
	c.ResponseWriter.WriteHeader(code)
	return json.NewEncoder(c.ResponseWriter).Encode(v)
}

func (c *Context) XML(code int, v interface{}) error {
	c.ResponseWriter.Header().Set("Content-Type", "application/xml")
	c.ResponseWriter.WriteHeader(code)
	return xml.NewEncoder(c.ResponseWriter).Encode(v)
}

func (c *Context) String(code int, format string, values ...interface{}) error {
	c.ResponseWriter.Header().Set("Content-Type", "text/plain")
	c.ResponseWriter.WriteHeader(code)
	_, err := fmt.Fprintf(c.ResponseWriter, format, values...)
	return err
}

// Security helpers
func (c *Context) SetSecureHeaders() {
	h := c.ResponseWriter.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-XSS-Protection", "1; mode=block")
	h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	h.Set("Content-Security-Policy", "default-src 'self'")
}
