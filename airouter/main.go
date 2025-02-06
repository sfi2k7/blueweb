package airouter

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"math"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type (
	Config struct {
		Router RouterConfig `toml:"router"`
		// Server ServerConfig `toml:"server"`
		// Compression CompressConfig   `toml:"compression"`
		// RateLimit   RateLimitConfig  `toml:"rate_limit"`
		// Static      StaticConfig     `toml:"static"`
		// Logging     LogConfig        `toml:"logging"`
		// Metrics     MetricsConfig    `toml:"metrics"`
		// Security    SecurityConfig   `toml:"security"`
		// Pool        PoolConfig       `toml:"pool"`
		// Tree        TreeConfig       `toml:"tree"`
		// Middleware  MiddlewareConfig `toml:"middleware"`
		// Errors      ErrorConfig      `toml:"errors"`
		// Health      HealthConfig     `toml:"health"`
		// Templates   TemplateConfig   `toml:"templates"`
	}

	RouterConfig struct {
		Debug                   bool `toml:"debug"`
		MaxParams               int  `toml:"max_params"`
		TrailingSlash           bool `toml:"trailing_slash"`
		CaseSensitive           bool `toml:"case_sensitive"`
		RedirectFixedPath       bool `toml:"redirect_fixed_path"`
		HandleOptions           bool `toml:"handle_options"`
		HandleMethodsNotAllowed bool `toml:"handle_methods_not_allowed"`
		HandleHead              bool `toml:"handle_head"`
		AutoOptions             bool `toml:"auto_options"`
	}
	// Handler is a custom handler function type
	Handler func(*Context)

	middlewareEntry struct {
		handler Middleware
		must    bool
	}
	// // node represents a segment in the routing tree
	// node struct {
	// 	path       string
	// 	isParam    bool
	// 	isCatchAll bool
	// 	handlers   map[string]Handler // HTTP method -> handler
	// 	children   []*node
	// }

	// Node types for optimization

	ParamDefinition struct {
		Name         string
		Regex        *regexp.Regexp
		IsOptional   bool
		DefaultValue string
	}

	StringMap struct {
		sync.RWMutex
		data map[string]string
	}

	// Cache interface for router caching
	Cache interface {
		Get(key string) (interface{}, bool)
		Set(key string, value interface{})
		Delete(key string)
	}

	Middleware func(*Context) bool

	// // Route represents a route group
	// Route struct {
	// 	prefix     string
	// 	router     *Router
	// 	middleware []Middleware
	// }

	// Context holds the request context
	Context struct {
		Request        *http.Request
		ResponseWriter http.ResponseWriter
		params         map[string]string
		query          map[string][]string
		queryParsed    bool
		headers        map[string][]string
		headersParsed  bool
		start          time.Time
		//2
		bodyParsed    bool
		jsonData      map[string]interface{}
		formData      url.Values
		multipartForm *multipart.Form
		maxMemory     int64
		err           error
		router        *Router
		store         map[string]interface{}
		aborted       bool
	}
)

// OptimizationConfig holds configuration for tree optimization
type OptimizationConfig struct {
	MergeCommonPrefixes bool
	SortByPriority      bool
	CompressChains      bool
	RemoveEmptyNodes    bool
	CacheRoutes         bool
}

// Pool for common request structures
type requestPool struct {
	jsonPool sync.Pool
	formPool sync.Pool
}

// Cache implementation
type RouterCache struct {
	cache sync.Map
}

func (c *RouterCache) Get(key string) (interface{}, bool) {
	return c.cache.Load(key)
}

func (c *RouterCache) Set(key string, value interface{}) {
	c.cache.Store(key, value)
}

func (c *RouterCache) Delete(key string) {
	c.cache.Delete(key)
}

// // Router configuration
// func NewRouter() *Router {
// 	r := &Router{
// 		cache:       &RouterCache{},
// 		maxBodySize: 10 << 20, // 10 MB
// 	}

// 	r.bodyPool.New = func() interface{} {
// 		return make([]byte, 32*1024) // 32 KB
// 	}

// 	// ... rest of initialization
// 	return r
// }

// Cache implementation for optimized routes
type RouteCache struct {
	cache sync.Map
}

func (rc *RouteCache) Get(path string) (*node, bool) {
	if value, ok := rc.cache.Load(path); ok {
		return value.(*node), true
	}
	return nil, false
}

func (rc *RouteCache) Set(path string, node *node) {
	rc.cache.Store(path, node)
}

// Helper function to extract parameter names from path
// func extractParams(path string) []string {
// 	var params []string
// 	segments := strings.Split(path, "/")
// 	for _, segment := range segments {
// 		if strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}") {
// 			param := strings.Trim(segment, "{}")
// 			params = append(params, param)
// 		}
// 	}
// 	return params
// }

// Abort stops the middleware chain execution
func (c *Context) Abort() {
	c.aborted = true
}

// Helper types

type pathSegment struct {
	value     string
	segtype   segmentType
	paramName string
}

type segmentType int

const (
	staticSegment segmentType = iota
	paramSegment
	catchAllSegment
)

type Route struct {
	Method     string
	Path       string
	Handler    Handler
	Middleware []Middleware
	Pattern    string
	Priority   int
	CreatedAt  time.Time
	MaxParams  int
	prefix     string
	router     *Router
	middleware []middlewareEntry
}

// // Usage example
// func main() {
//     router := NewRouter()

//     // Add routes
//     err := router.Add("GET", "/users/{id}", handleUser,
//         LogMiddleware,
//         AuthMiddleware,
//         RateLimitMiddleware,
//     )
//     if err != nil {
//         log.Fatal(err)
//     }

//     err = router.Add("POST", "/users", createUser,
//         LogMiddleware,
//         AuthMiddleware,
//         ValidateMiddleware,
//     )
//     if err != nil {
//         log.Fatal(err)
//     }

//     // Add catch-all route
//     err = router.Add("GET", "/files/*path", handleFiles,
//         LogMiddleware,
//         AuthMiddleware,
//     )
//     if err != nil {
//         log.Fatal(err)
//     }

//     // Start server
//     log.Fatal(http.ListenAndServe(":8080", router))
// }

// Group method handlers
func (g *Route) Get(path string, handlers ...Handler) {
	g.Add(http.MethodGet, path, handlers...)
}

func (g *Route) Post(path string, handlers ...Handler) {
	g.Add(http.MethodPost, path, handlers...)
}

func (g *Route) Put(path string, handlers ...Handler) {
	g.Add(http.MethodPut, path, handlers...)
}

func (g *Route) Delete(path string, handlers ...Handler) {
	g.Add(http.MethodDelete, path, handlers...)
}

// Add for route group
func (g *Route) Add(method, path string, handlers ...Handler) {
	fullPath := g.prefix + path

	// Combine group middleware with route handlers
	finalHandlers := make([]Handler, 0, len(g.middleware)+len(handlers))

	// Create a chain of handlers starting with the last handler
	h := handlers[len(handlers)-1]
	for i := len(g.middleware) - 1; i >= 0; i-- {
		h = g.middleware[i]
		finalHandlers = append(finalHandlers, h)
	}

	g.router.Add(method, fullPath, finalHandlers...)
}

// // Add adds a new route with handler for a specific HTTP method
// func (r *Router) Add(method, path string, handlers ...Handler) {
// 	// Combine global middleware with route handlers
// 	finalHandlers := make([]Handler, 0, len(r.middleware)+len(handlers))

// 	// Create a chain of handlers starting with the last middleware
// 	h := handlers[len(handlers)-1]
// 	for i := len(r.middleware) - 1; i >= 0; i-- {
// 		h = r.middleware[i](h)
// 	}
// 	finalHandlers = append(finalHandlers, h)

// 	segments := strings.Split(strings.Trim(path, "/"), "/")
// 	current := r.tree

// 	for _, segment := range segments {
// 		isParam := strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}")
// 		isCatchAll := segment == "*path"

// 		current.priority++
// 		var child *node
// 		for _, n := range current.children {
// 			if n.path == segment {
// 				child = n
// 				break
// 			}
// 		}

// 		for _, n := range current.children {
// 			if n.path == segment {
// 				child = n
// 				break
// 			}
// 		}

// 		// var child *node
// 		// for _, n := range current.children {
// 		// 	if n.path == segment {
// 		// 		child = n
// 		// 		break
// 		// 	}
// 		// }

// 		// if child != nil {
// 		// 	current = child
// 		// }

// 		if child == nil {
// 			child = &node{
// 				path:       segment,
// 				isParam:    isParam,
// 				isCatchAll: isCatchAll,
// 				handlers:   make(map[string][]Handler),
// 			}
// 			current.children = append(current.children, child)
// 		}

// 		current = child
// 	}

// 	current.handlers[method] = finalHandlers
// }

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

// extractParams extracts URL parameters from path
func extractParams(path string, node *node) *Params {
	params := NewParams(node.router.maxParams)
	segments := strings.Split(strings.Trim(path, "/"), "/")
	currentNode := node

	for i, segment := range segments {
		if segment == "" {
			continue
		}

		// Handle parameter nodes
		if currentNode.nodeType == paramNode {
			params.Add(currentNode.paramName, segment)
		}

		// Handle catch-all nodes
		if currentNode.nodeType == catchAllNode {
			remainingPath := strings.Join(segments[i:], "/")
			params.Add(currentNode.paramName, remainingPath)
			break
		}

		// Move to next node
		for _, child := range currentNode.children {
			if child.nodeType == staticNode && child.segment == segment {
				currentNode = child
				break
			}
			if child.nodeType == paramNode || child.nodeType == catchAllNode {
				currentNode = child
				break
			}
		}
	}

	return params
}

// Additional helper methods for parameter handling
type ParamExtractor struct {
	path   string
	params *Params
	node   *node
}

func NewParamExtractor(path string, node *node) *ParamExtractor {
	return &ParamExtractor{
		path:   path,
		params: NewParams(node.router.maxParams),
		node:   node,
	}
}

func (pe *ParamExtractor) Extract() *Params {
	if pe.node == nil {
		return pe.params
	}

	segments := pe.splitPath()
	pe.processSegments(segments, pe.node)
	return pe.params
}

func (pe *ParamExtractor) splitPath() []string {
	return strings.Split(strings.Trim(pe.path, "/"), "/")
}

func (pe *ParamExtractor) processSegments(segments []string, currentNode *node) {
	for i, segment := range segments {
		if segment == "" {
			continue
		}

		switch currentNode.nodeType {
		case paramNode:
			pe.params.Add(currentNode.paramName, segment)
		case catchAllNode:
			remainingPath := strings.Join(segments[i:], "/")
			pe.params.Add(currentNode.paramName, remainingPath)
			return
		}

		// Find next node
		nextNode := pe.findNextNode(segment, currentNode)
		if nextNode == nil {
			return
		}
		currentNode = nextNode
	}
}

func (pe *ParamExtractor) findNextNode(segment string, currentNode *node) *node {
	// Try static nodes first
	for _, child := range currentNode.children {
		if child.nodeType == staticNode && child.segment == segment {
			return child
		}
	}

	// Try parameter nodes
	for _, child := range currentNode.children {
		if child.nodeType == paramNode || child.nodeType == catchAllNode {
			return child
		}
	}

	return nil
}

// // Usage example
// func main() {
//     router := NewRouter()

//     // Register routes
//     router.Get("/users/{id}", func(c *Context) {
//         id := c.Params.Get("id")
//         c.String(200, "User ID: %s", id)
//     })

//     router.Get("/files/*path", func(c *Context) {
//         path := c.Params.Get("path")
//         c.String(200, "File path: %s", path)
//     })

//     // Example request
//     req, _ := http.NewRequest("GET", "/users/123", nil)
//     w := httptest.NewRecorder()

//     // Handle request
//     router.ServeHTTP(w, req)

//     // Find route and extract params
//     node := router.tree.findRoute("/users/123", nil)
//     if node != nil {
//         params := extractParams("/users/123", node)
//         fmt.Println("User ID:", params.Get("id")) // Output: User ID: 123
//     }

//     // Using ParamExtractor
//     extractor := NewParamExtractor("/users/123", node)
//     params := extractor.Extract()
//     fmt.Println("User ID:", params.Get("id")) // Output: User ID: 123
// }

// // Add route with priority tracking
// func (r *Router) Add(method, path string, handlers ...Handler) {
// 	// Existing add logic...

// 	// Update node priorities
// 	segments := strings.Split(strings.Trim(path, "/"), "/")
// 	current := r.tree
// 	for _, segment := range segments {
// 		current.priority++
// 		var child *node
// 		for _, n := range current.children {
// 			if n.path == segment {
// 				child = n
// 				break
// 			}
// 		}

// 		if child != nil {
// 			current = child
// 		}
// 	}
// }

// Reset resets the context for reuse
func (c *Context) Reset(w http.ResponseWriter, r *http.Request) {
	c.Request = r
	c.ResponseWriter = w
	c.queryParsed = false
	c.headersParsed = false
	c.start = time.Now()
	c.router = nil
	for k := range c.params {
		delete(c.params, k)
	}
}

// Param gets a URL parameter value
func (c *Context) Param(name string) string {
	return c.params[name]
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

// Extended RouteStats structure
type RouteStats struct {
	TotalNodes            int
	StaticNodes           int
	ParamNodes            int
	CatchAllNodes         int
	HandlerNodes          int
	ChildNodes            int
	CommonPrefixes        int
	MaxDepth              int
	AverageDepth          float64
	MaxBranchingFactor    int
	TotalBranches         int
	PathDepthDistribution map[int]int

	// Additional analysis
	Complexity        float64 // Measure of tree complexity
	OptimizationScore float64 // Score indicating optimization potential
	MemoryUsage       int64   // Estimated memory usage
	SearchComplexity  string  // Best/Average/Worst case search complexity
}

// NewRouteStats creates a new RouteStats instance
func NewRouteStats() *RouteStats {
	return &RouteStats{
		PathDepthDistribution: make(map[int]int),
	}
}

// Finalize calculates final statistics
func (s *RouteStats) Finalize() {
	if s.TotalNodes > 0 {
		// Calculate average depth
		s.AverageDepth = s.AverageDepth / float64(s.TotalNodes)

		// Calculate average branching factor
		avgBranching := float64(s.TotalBranches) / float64(s.TotalNodes)

		// Calculate tree complexity
		s.Complexity = float64(s.MaxDepth) * avgBranching

		// Calculate optimization score
		s.OptimizationScore = s.calculateOptimizationScore()

		// Estimate memory usage
		s.MemoryUsage = s.estimateMemoryUsage()

		// Determine search complexity
		s.SearchComplexity = s.determineSearchComplexity()
	}
}

// Helper methods for RouteStats
func (s *RouteStats) calculateOptimizationScore() float64 {
	score := 100.0

	// Penalize high average depth
	if s.AverageDepth > 5 {
		score -= (s.AverageDepth - 5) * 5
	}

	// Penalize low static/param ratio
	if s.StaticNodes > 0 {
		staticParamRatio := float64(s.ParamNodes) / float64(s.StaticNodes)
		if staticParamRatio > 0.5 {
			score -= (staticParamRatio - 0.5) * 20
		}
	}

	// Penalize high branching factor
	if s.MaxBranchingFactor > 10 {
		score -= float64(s.MaxBranchingFactor-10) * 2
	}

	// Reward common prefix usage
	score += float64(s.CommonPrefixes) * 2

	return math.Max(0, score)
}

func (s *RouteStats) estimateMemoryUsage() int64 {
	// Rough estimation of memory usage
	nodeSize := int64(56)    // Base node structure size
	handlerSize := int64(32) // Estimated size per handler

	total := nodeSize * int64(s.TotalNodes)
	total += handlerSize * int64(s.HandlerNodes)

	return total
}

func (s *RouteStats) determineSearchComplexity() string {
	switch {
	case s.MaxDepth <= 3 && s.MaxBranchingFactor <= 5:
		return "O(1) - Constant"
	case s.MaxDepth <= 10:
		return "O(log n) - Logarithmic"
	default:
		return "O(n) - Linear"
	}
}

// String representation of RouteStats
func (s *RouteStats) String() string {
	return fmt.Sprintf(`Route Tree Analysis:
    Total Nodes: %d
    Static Nodes: %d
    Parameter Nodes: %d
    Catch-All Nodes: %d
    Handler Nodes: %d
    Common Prefixes: %d
    Max Depth: %d
    Average Depth: %.2f
    Max Branching Factor: %d
    Complexity Score: %.2f
    Optimization Score: %.2f
    Estimated Memory: %d bytes
    Search Complexity: %s
    
    Path Depth Distribution:
    %s`,
		s.TotalNodes,
		s.StaticNodes,
		s.ParamNodes,
		s.CatchAllNodes,
		s.HandlerNodes,
		s.CommonPrefixes,
		s.MaxDepth,
		s.AverageDepth,
		s.MaxBranchingFactor,
		s.Complexity,
		s.OptimizationScore,
		s.MemoryUsage,
		s.SearchComplexity,
		s.formatDepthDistribution(),
	)
}

func (s *RouteStats) formatDepthDistribution() string {
	var depths []int
	for depth := range s.PathDepthDistribution {
		depths = append(depths, depth)
	}
	sort.Ints(depths)

	var builder strings.Builder
	for _, depth := range depths {
		count := s.PathDepthDistribution[depth]
		builder.WriteString(fmt.Sprintf("        Depth %d: %d paths\n", depth, count))
	}
	return builder.String()
}
