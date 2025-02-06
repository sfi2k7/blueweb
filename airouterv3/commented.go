package airouterv3

// // ServeHTTP implements http.Handler interface
// func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
// 	ctx := r.pool.Get().(*Context)
// 	ctx.Reset(w, req)
// 	defer r.pool.Put(ctx)

// 	segments := strings.Split(strings.Trim(req.URL.Path, "/"), "/")
// 	current := r.tree

// 	for i, segment := range segments {
// 		found := false

// 		for _, child := range current.children {
// 			if child.isCatch {
// 				ctx.params["path"] = strings.Join(segments[i:], "/")
// 				current = child
// 				found = true
// 				break
// 			}

// 			if child.path == segment || child.isParam {
// 				if child.isParam {
// 					ctx.params[child.paramName] = segment
// 				}
// 				current = child
// 				found = true
// 				break
// 			}
// 		}

// 		if !found {
// 			r.NotFound(ctx)
// 			return
// 		}
// 	}

// 	if handler, ok := current.handlers[req.Method]; ok {
// 		handler(ctx)
// 	} else {
// 		r.NotFound(ctx)
// 	}
// }

// Context methods

//

// // Statistics and analysis
// type RouteStats struct {
// 	TotalNodes     int
// 	StaticNodes    int
// 	ParamNodes     int
// 	CatchAllNodes  int
// 	AverageDepth   float64
// 	MaxDepth       int
// 	CommonPrefixes int
// }

// func (r *Router) analyzeTree() RouteStats {
// 	stats := RouteStats{}
// 	r.tree.analyze(&stats, 0)
// 	return stats
// }

// // Usage example
// func main() {
// 	router := NewRouter()

// 	// Add routes
// 	router.Get("/users", handleUsers)
// 	router.Get("/users/{id}", handleUser)
// 	router.Get("/users/{id}/profile", handleProfile)
// 	router.Get("/users/{id}/settings", handleSettings)
// 	router.Get("/admin/users", handleAdminUsers)
// 	router.Get("/admin/users/{id}", handleAdminUser)

// 	// Optimize the tree
// 	router.optimizeTree()

// 	// Print statistics
// 	stats := router.analyzeTree()
// 	fmt.Printf("Router Statistics:\n")
// 	fmt.Printf("Total Nodes: %d\n", stats.TotalNodes)
// 	fmt.Printf("Static Nodes: %d\n", stats.StaticNodes)
// 	fmt.Printf("Parameter Nodes: %d\n", stats.ParamNodes)
// 	fmt.Printf("Average Depth: %.2f\n", stats.AverageDepth)
// }

// // analyze collects statistics about the routing tree
// func (n *node) analyze(stats *RouteStats, depth int) {
// 	if n == nil {
// 		return
// 	}

// 	// Update total nodes count
// 	stats.TotalNodes++

// 	// Update node type counts
// 	switch n.nodeType {
// 	case staticNode:
// 		stats.StaticNodes++
// 	case paramNode:
// 		stats.ParamNodes++
// 	case catchAllNode:
// 		stats.CatchAllNodes++
// 	}

// 	// Update depth statistics
// 	if depth > stats.MaxDepth {
// 		stats.MaxDepth = depth
// 	}

// 	// Calculate average depth (will be divided by TotalNodes later)
// 	stats.AverageDepth += float64(depth)

// 	// Count common prefixes
// 	if len(n.children) > 1 {
// 		prefix := longestCommonPrefix(n.children)
// 		if len(prefix) > 0 {
// 			stats.CommonPrefixes++
// 		}
// 	}

// 	// Additional statistics
// 	stats.ChildNodes += len(n.children)
// 	if len(n.handlers) > 0 {
// 		stats.HandlerNodes++
// 	}

// 	// Calculate branching factor
// 	if len(n.children) > stats.MaxBranchingFactor {
// 		stats.MaxBranchingFactor = len(n.children)
// 	}
// 	stats.TotalBranches += len(n.children)

// 	// Calculate path depth distribution
// 	pathDepth := len(strings.Split(n.fullPath, "/"))
// 	stats.PathDepthDistribution[pathDepth]++

// 	// Recursively analyze children
// 	for _, child := range n.children {
// 		child.analyze(stats, depth+1)
// 	}
// }

// // Extended RouteStats structure
// type RouteStats struct {
// 	TotalNodes            int
// 	StaticNodes           int
// 	ParamNodes            int
// 	CatchAllNodes         int
// 	HandlerNodes          int
// 	ChildNodes            int
// 	CommonPrefixes        int
// 	MaxDepth              int
// 	AverageDepth          float64
// 	MaxBranchingFactor    int
// 	TotalBranches         int
// 	PathDepthDistribution map[int]int

// 	// Additional analysis
// 	Complexity        float64 // Measure of tree complexity
// 	OptimizationScore float64 // Score indicating optimization potential
// 	MemoryUsage       int64   // Estimated memory usage
// 	SearchComplexity  string  // Best/Average/Worst case search complexity
// }

// // NewRouteStats creates a new RouteStats instance
// func NewRouteStats() *RouteStats {
// 	return &RouteStats{
// 		PathDepthDistribution: make(map[int]int),
// 	}
// }

// Finalize calculates final statistics
// func (s *RouteStats) Finalize() {
// 	if s.TotalNodes > 0 {
// 		// Calculate average depth
// 		s.AverageDepth = s.AverageDepth / float64(s.TotalNodes)

// 		// Calculate average branching factor
// 		avgBranching := float64(s.TotalBranches) / float64(s.TotalNodes)

// 		// Calculate tree complexity
// 		s.Complexity = float64(s.MaxDepth) * avgBranching

// 		// Calculate optimization score
// 		s.OptimizationScore = s.calculateOptimizationScore()

// 		// Estimate memory usage
// 		s.MemoryUsage = s.estimateMemoryUsage()

// 		// Determine search complexity
// 		s.SearchComplexity = s.determineSearchComplexity()
// 	}
// }

// // Helper methods for RouteStats
// func (s *RouteStats) calculateOptimizationScore() float64 {
// 	score := 100.0

// 	// Penalize high average depth
// 	if s.AverageDepth > 5 {
// 		score -= (s.AverageDepth - 5) * 5
// 	}

// 	// Penalize low static/param ratio
// 	if s.StaticNodes > 0 {
// 		staticParamRatio := float64(s.ParamNodes) / float64(s.StaticNodes)
// 		if staticParamRatio > 0.5 {
// 			score -= (staticParamRatio - 0.5) * 20
// 		}
// 	}

// 	// Penalize high branching factor
// 	if s.MaxBranchingFactor > 10 {
// 		score -= float64(s.MaxBranchingFactor-10) * 2
// 	}

// 	// Reward common prefix usage
// 	score += float64(s.CommonPrefixes) * 2

// 	return math.Max(0, score)
// }

// func (s *RouteStats) estimateMemoryUsage() int64 {
// 	// Rough estimation of memory usage
// 	nodeSize := int64(56)    // Base node structure size
// 	handlerSize := int64(32) // Estimated size per handler

// 	total := nodeSize * int64(s.TotalNodes)
// 	total += handlerSize * int64(s.HandlerNodes)

// 	return total
// }

// func (s *RouteStats) determineSearchComplexity() string {
// 	switch {
// 	case s.MaxDepth <= 3 && s.MaxBranchingFactor <= 5:
// 		return "O(1) - Constant"
// 	case s.MaxDepth <= 10:
// 		return "O(log n) - Logarithmic"
// 	default:
// 		return "O(n) - Linear"
// 	}
// }

// // String representation of RouteStats
// func (s *RouteStats) String() string {
// 	return fmt.Sprintf(`Route Tree Analysis:
//     Total Nodes: %d
//     Static Nodes: %d
//     Parameter Nodes: %d
//     Catch-All Nodes: %d
//     Handler Nodes: %d
//     Common Prefixes: %d
//     Max Depth: %d
//     Average Depth: %.2f
//     Max Branching Factor: %d
//     Complexity Score: %.2f
//     Optimization Score: %.2f
//     Estimated Memory: %d bytes
//     Search Complexity: %s

//     Path Depth Distribution:
//     %s`,
// 		s.TotalNodes,
// 		s.StaticNodes,
// 		s.ParamNodes,
// 		s.CatchAllNodes,
// 		s.HandlerNodes,
// 		s.CommonPrefixes,
// 		s.MaxDepth,
// 		s.AverageDepth,
// 		s.MaxBranchingFactor,
// 		s.Complexity,
// 		s.OptimizationScore,
// 		s.MemoryUsage,
// 		s.SearchComplexity,
// 		s.formatDepthDistribution(),
// 	)
// }

// func (s *RouteStats) formatDepthDistribution() string {
// 	var depths []int
// 	for depth := range s.PathDepthDistribution {
// 		depths = append(depths, depth)
// 	}
// 	sort.Ints(depths)

// 	var builder strings.Builder
// 	for _, depth := range depths {
// 		count := s.PathDepthDistribution[depth]
// 		builder.WriteString(fmt.Sprintf("        Depth %d: %d paths\n", depth, count))
// 	}
// 	return builder.String()
// }

// Add these imports at the top
// import (
//     "crypto/tls"
//     "golang.org/x/crypto/acme/autocert"
//     "log"
// )

// // Add these types to the Router struct
// type SSLConfig struct {
//     Enabled      bool
//     Certificate  string
//     PrivateKey   string
//     AutoTLS      bool
//     Domains      []string
//     CertCache    string
// }

// // Add these methods to the Router implementation

// // ListenAndServe starts the server with optional SSL support
// func (r *Router) ListenAndServe(addr string, sslConfig *SSLConfig) error {
//     if !r.optimized {
//         r.Optimize()
//     }

//     server := &http.Server{
//         Addr:    addr,
//         Handler: r,
//     }

//     if sslConfig != nil && sslConfig.Enabled {
//         if sslConfig.AutoTLS {
//             return r.serveAutoTLS(server, sslConfig)
//         }
//         return r.serveManualTLS(server, sslConfig)
//     }

//     return server.ListenAndServe()
// }

// // serveAutoTLS starts the server with automatic SSL certificate management
// func (r *Router) serveAutoTLS(server *http.Server, config *SSLConfig) error {
//     if len(config.Domains) == 0 {
//         return fmt.Errorf("no domains specified for AutoTLS")
//     }

//     certManager := &autocert.Manager{
//         Prompt:     autocert.AcceptTOS,
//         HostPolicy: autocert.HostWhitelist(config.Domains...),
//     }

//     // Set certificate cache directory if specified
//     if config.CertCache != "" {
//         certManager.Cache = autocert.DirCache(config.CertCache)
//     }

//     // Configure TLS
//     server.TLSConfig = &tls.Config{
//         GetCertificate: certManager.GetCertificate,
//         MinVersion:     tls.VersionTLS12,
//     }

//     // Start HTTP-01 challenge handler
//     go func() {
//         log.Printf("Starting HTTP-01 challenge handler on :80")
//         if err := http.ListenAndServe(":80", certManager.HTTPHandler(nil)); err != nil {
//             log.Printf("HTTP-01 challenge handler error: %v", err)
//         }
//     }()

//     log.Printf("Starting HTTPS server on %s", server.Addr)
//     return server.ListenAndServeTLS("", "")
// }

// // serveManualTLS starts the server with manual SSL certificate management
// func (r *Router) serveManualTLS(server *http.Server, config *SSLConfig) error {
//     if config.Certificate == "" || config.PrivateKey == "" {
//         return fmt.Errorf("certificate and private key files are required for manual TLS")
//     }

//     // Configure TLS
//     server.TLSConfig = &tls.Config{
//         MinVersion: tls.VersionTLS12,
//     }

//     log.Printf("Starting HTTPS server on %s", server.Addr)
//     return server.ListenAndServeTLS(config.Certificate, config.PrivateKey)
// }

// // Helper method to create SSL config
// func NewSSLConfig() *SSLConfig {
//     return &SSLConfig{
//         Enabled: false,
//     }
// }

// // Configure manual SSL
// func (c *SSLConfig) WithCertificate(certFile, keyFile string) *SSLConfig {
//     c.Enabled = true
//     c.AutoTLS = false
//     c.Certificate = certFile
//     c.PrivateKey = keyFile
//     return c
// }

// // Configure Auto SSL with Let's Encrypt
// func (c *SSLConfig) WithAutoTLS(domains []string, cacheDir string) *SSLConfig {
//     c.Enabled = true
//     c.AutoTLS = true
//     c.Domains = domains
//     c.CertCache = cacheDir
//     return c
// }

// func main() {
// 	router := New()

// 	// Add your routes
// 	router.Get("/", handleHome)
// 	router.Get("/api/{version}/*path", handleAPI)

// 	// Example 1: Start server without SSL
// 	router.ListenAndServe(":8080", nil)

// 	// Example 2: Start server with manual SSL certificates
// 	sslConfig := NewSSLConfig().WithCertificate(
// 		"/path/to/cert.pem",
// 		"/path/to/key.pem",
// 	)
// 	router.ListenAndServe(":443", sslConfig)

// 	// Example 3: Start server with Auto SSL (Let's Encrypt)
// 	autoSSLConfig := NewSSLConfig().WithAutoTLS(
// 		[]string{"example.com", "www.example.com"},
// 		"/var/www/.cache",
// 	)
// 	router.ListenAndServe(":443", autoSSLConfig)
// }

// // Example with more complete setup
// func main() {
// 	router := New()

// 	// Add routes
// 	router.Get("/", handleHome)
// 	router.Get("/api/{version}/*path", handleAPI)

// 	// Optimize routes
// 	router.Optimize()

// 	// Configure SSL
// 	sslConfig := NewSSLConfig().WithAutoTLS(
// 		[]string{"example.com", "www.example.com"},
// 		"/var/www/.cache",
// 	)

// 	// Start server with graceful shutdown
// 	server := &http.Server{
// 		Addr:    ":443",
// 		Handler: router,
// 	}

// 	// Graceful shutdown handling
// 	go func() {
// 		if err := router.ListenAndServe(":443", sslConfig); err != nil &&
// 			err != http.ErrServerClosed {
// 			log.Fatalf("Server error: %v", err)
// 		}
// 	}()

// 	// Wait for interrupt signal
// 	quit := make(chan os.Signal, 1)
// 	signal.Notify(quit, os.Interrupt)
// 	<-quit

// 	// Graceful shutdown
// 	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
// 	defer cancel()

// 	if err := server.Shutdown(ctx); err != nil {
// 		log.Fatalf("Server forced to shutdown: %v", err)
// 	}

// 	log.Println("Server exiting")
// }

// // ServeHTTP implements http.Handler
// func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
// 	ctx := r.pool.Get().(*Context)
// 	ctx.Reset(w, req)
// 	defer r.pool.Put(ctx)

// 	// Run must-run middleware
// 	for _, mw := range r.mustMiddleware {
// 		if mw(ctx) == Abort {
// 			return
// 		}
// 	}

// 	// Run regular middleware
// 	for _, mw := range r.middleware {
// 		if !mw(ctx) {
// 			return
// 		}
// 	}

// 	// Find and execute route
// 	node, params := r.findRoute(req.URL.Path)

// 	if node == nil {
// 		r.NotFound(ctx)
// 		return
// 	}

// 	ctx.params = params

// 	if handler, ok := node.handlers[req.Method]; ok {
// 		handler(ctx)
// 	} else {
// 		r.NotFound(ctx)
// 	}
// }

// findRoute finds a route in the tree
// func (r *Router) findRoute(path string) (*node, *Params) {
// 	if path == "/" {
// 		return r.tree, nil
// 	}

// 	segments := strings.Split(strings.Trim(path, "/"), "/")
// 	current := r.tree
// 	params := NewParams(10)

// 	for _, segment := range segments {
// 		found := false

// 		for _, child := range current.children {
// 			if child.path == segment || child.isParam {
// 				if child.isParam {
// 					params.Add(child.paramName, segment)
// 				}
// 				current = child
// 				found = true
// 				break
// 			}
// 		}

// 		if !found {
// 			return nil, nil
// 		}
// 	}

// 	return current, params
// }

// func (r *Router) PrintRoutes() {
//     fmt.Println("Router Tree:")
//     r.printNode(r.tree, 0)
// }

// func (r *Router) printNode(n *node, level int) {
//     if n == nil {
//         return
//     }

//     indent := strings.Repeat("  ", level)
//     fmt.Printf("%sPath: %s (Type: %v)\n", indent, n.path, n.nodeType)
//     fmt.Printf("%sHandlers: %v\n", indent, n.handlers)

//     for _, child := range n.children {
//         r.printNode(child, level+1)
//     }
// }

// func (r *Router) Add(method, path string, handler Handler) {
// 	fmt.Printf("Registering route: %s %s\n", method, path)

// 	if path == "/" {
// 		r.tree.handlers[method] = handler
// 		return
// 	}

// 	segments := strings.Split(strings.Trim(path, "/"), "/")
// 	current := r.tree

// 	for _, segment := range segments {
// 		var child *node
// 		isParam := strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}")

// 		// Find existing child
// 		for _, n := range current.children {
// 			if n.path == segment {
// 				child = n
// 				break
// 			}
// 		}

// 		// Create new child if not found
// 		if child == nil {
// 			paramName := ""
// 			if isParam {
// 				paramName = segment[1 : len(segment)-1]
// 			}

// 			child = &node{
// 				path:      segment,
// 				handlers:  make(map[string]Handler),
// 				children:  make([]*node, 0),
// 				isParam:   isParam,
// 				paramName: paramName,
// 			}
// 			current.children = append(current.children, child)
// 		}

// 		current = child
// 	}

// 	current.handlers[method] = handler
// }

// func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
// 	ctx := r.pool.Get().(*Context)
// 	ctx.Reset(w, req)
// 	defer r.pool.Put(ctx)

// 	// Run must-run middleware first
// 	for _, mw := range r.mustMiddleware {
// 		if mw(ctx) == Abort {
// 			return
// 		}
// 	}

// 	// Run regular middleware chain
// 	for _, mw := range r.middleware {
// 		if !mw(ctx) {
// 			return
// 		}
// 	}

// 	// Find and execute route handler
// 	node, params := r.findRoute(req.URL.Path)
// 	if node == nil {
// 		r.NotFound(ctx)
// 		return
// 	}

// 	ctx.params = params.GetAll()

// 	if handler, ok := node.handlers[req.Method]; ok {
// 		handler(ctx)
// 	} else {
// 		r.NotFound(ctx)
// 	}
// }

// func (r *Router) checkConflicts(path string) error {
// 	segments := strings.Split(strings.Trim(path, "/"), "/")
// 	current := r.tree

// 	for _, segment := range segments {
// 		for _, child := range current.children {
// 			if child.path != segment &&
// 				((child.isParam && !strings.HasPrefix(segment, "{")) ||
// 					(child.isCatch && segment != "*path")) {
// 				return fmt.Errorf("route conflict at segment: %s", segment)
// 			}
// 		}
// 	}
// 	return nil
// }

// // Optimize prepares the router for high-performance routing
// func (r *Router) Optimize() {
// 	if r.optimized {
// 		return
// 	}

// 	r.routeCache = &RouteCache{}
// 	r.optimizeNode(r.tree)
// 	r.optimized = true
// }

// // optimizeNode recursively optimizes the routing tree
// func (r *Router) optimizeNode(n *node) {
// 	// Set node type
// 	if n.isCatch {
// 		n.nodeType = catchAllNode
// 		n.paramName = "path"
// 	} else if n.isParam {
// 		n.nodeType = paramNode
// 	} else {
// 		n.nodeType = staticNode
// 	}

// 	// Set segment
// 	n.segment = strings.TrimSuffix(strings.TrimPrefix(n.path, "{"), "}")

// 	// Optimize children
// 	for _, child := range n.children {
// 		r.optimizeNode(child)
// 	}
// }

// func (r *Router) Add(method, path string, handler Handler) {
// 	fmt.Printf("Registering route: %s %s\n", method, path)
// 	if err := r.checkConflicts(path); err != nil {
// 		panic(err)
// 	}

// 	fmt.Printf("Registering route: %s %s\n", method, path)

// 	// Special handling for root path
// 	if path == "/" {
// 		fmt.Println("Registering root handler")
// 		r.tree.handlers[method] = handler
// 		return
// 	}

// 	segments := strings.Split(strings.Trim(path, "/"), "/")
// 	current := r.tree
// 	for _, segment := range segments {
// 		fmt.Printf("Processing segment: %s\n", segment)
// 		var child *node
// 		isParam := strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}")
// 		isCatch := segment == "*path"

// 		for _, n := range current.children {
// 			if n.path == segment {
// 				child = n
// 				break
// 			}
// 		}

// 		if child == nil {
// 			child = &node{
// 				path:     segment,
// 				isParam:  isParam,
// 				handlers: make(map[string]Handler),
// 			}

// 			if isParam {
// 				child.nodeType = paramNode
// 				child.paramName = segment[1 : len(segment)-1]
// 			}

// 			if isCatch {
// 				child.nodeType = catchAllNode
// 				child.paramName = "path"
// 			}

// 			current.children = append(current.children, child)
// 			fmt.Printf("Created new node: %s (type: %v)\n", child.path, child.nodeType)
// 		}

// 		// fmt.Printf("Adding child %+v\n", child)
// 		current = child
// 	}

// 	current.handlers[method] = handler
// 	fmt.Printf("Added handler for %s at node: %s\n", method, current.path)
// 	// fmt.Printf("Adding Handler %+v\n", current)
// 	r.optimized = false // Reset optimization flag
// }

// // Add adds a new route with handler for a specific method
// func (r *Router) Add(method, path string, handler Handler) {
// 	segments := strings.Split(strings.Trim(path, "/"), "/")
// 	current := r.tree

// 	for _, segment := range segments {
// 		var child *node
// 		isParam := strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}")
// 		isCatch := segment == "*path"

// 		// Find existing child
// 		for _, n := range current.children {
// 			if n.path == segment {
// 				child = n
// 				break
// 			}
// 		}

// 		// Create new child if not found
// 		if child == nil {
// 			child = &node{
// 				path:     segment,
// 				isParam:  isParam,
// 				isCatch:  isCatch,
// 				handlers: make(map[string]Handler),
// 			}

// 			if isParam {
// 				child.paramName = segment[1 : len(segment)-1]
// 			}

// 			current.children = append(current.children, child)
// 		}

// 		current = child
// 	}

// 	current.handlers[method] = handler
// }

// Router is the main router struct
// type Router struct {
// 	tree           *node
// 	pool           sync.Pool
// 	NotFound       Handler
// 	routeCache     *RouteCache
// 	optimized      bool
// 	middleware     []Middleware     // Add this
// 	mustMiddleware []MustMiddleware // Add this
// }

// type nodeType int

// const (
// 	staticNode nodeType = iota
// 	paramNode
// 	catchAllNode
// )

// // node represents a router trie node
// type node struct {
// 	id        string
// 	path      string
// 	isParam   bool
// 	isCatch   bool
// 	handlers  map[string]Handler
// 	children  []*node
// 	paramName string
// 	router    *Router
// 	nodeType  nodeType
// 	segment   string
// 	// handler   Handler
// }

// // extractParams extracts URL parameters from path
// func extractParams(path string, node *node) *Params {
// 	params := NewParams(10)
// 	segments := strings.Split(strings.Trim(path, "/"), "/")
// 	currentNode := node

// 	for i, segment := range segments {
// 		if segment == "" {
// 			continue
// 		}

// 		// Handle parameter nodes
// 		if currentNode.nodeType == paramNode {
// 			params.Add(currentNode.paramName, segment)
// 		}

// 		// Handle catch-all nodes
// 		if currentNode.nodeType == catchAllNode {
// 			remainingPath := strings.Join(segments[i:], "/")
// 			params.Add(currentNode.paramName, remainingPath)
// 			break
// 		}

// 		// Move to next node
// 		for _, child := range currentNode.children {
// 			if child.nodeType == staticNode && child.segment == segment {
// 				currentNode = child
// 				break
// 			}
// 			if child.nodeType == paramNode || child.nodeType == catchAllNode {
// 				currentNode = child
// 				break
// 			}
// 		}
// 	}

// 	return params
// }

// // getParamChild returns parameter child node if exists
// func (n *node) getParamChild() *node {
// 	if n == nil || len(n.children) == 0 {
// 		return nil
// 	}

// 	for _, child := range n.children {
// 		if child.nodeType == paramNode {
// 			return child
// 		}
// 	}
// 	return nil
// }

// // getStaticChild returns static child node matching the segment
// func (n *node) getStaticChild(segment string) *node {
// 	if n == nil || len(n.children) == 0 {
// 		return nil
// 	}

// 	for _, child := range n.children {
// 		if child.nodeType == staticNode && child.segment == segment {
// 			return child
// 		}
// 	}
// 	return nil
// }

// // getCatchAllChild returns catch-all child node if exists
// func (n *node) getCatchAllChild() *node {
// 	if n == nil || len(n.children) == 0 {
// 		return nil
// 	}

// 	for _, child := range n.children {
// 		if child.nodeType == catchAllNode {
// 			return child
// 		}
// 	}
// 	return nil
// }

// func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
// 	ctx := r.pool.Get().(*Context)
// 	ctx.Reset(w, req)
// 	defer r.pool.Put(ctx)

// 	// Ensure router is optimized
// 	if !r.optimized {
// 		r.Optimize()
// 	}

// 	// Run must-run middleware first
// 	for _, mw := range r.mustMiddleware {
// 		if mw(ctx) == Abort {
// 			return
// 		}
// 	}

// 	// Run regular middleware chain
// 	for _, mw := range r.middleware {
// 		if !mw(ctx) {
// 			return
// 		}
// 	}

// 	fmt.Printf("Processing request: %s %s\n", req.Method, req.URL.Path)

// 	// Find route
// 	// params := NewParams(10)
// 	node, params := r.findRoute(req.URL.Path)

// 	if node == nil {
// 		fmt.Printf("No route found for: %s\n", req.URL.Path)
// 		r.NotFound(ctx)
// 		return
// 	}

// 	// Set parameters
// 	ctx.params = params

// 	// Execute handler
// 	if handler, ok := node.handlers[req.Method]; ok {
// 		fmt.Printf("Executing handler for: %s %s\n", req.Method, req.URL.Path)
// 		handler(ctx)
// 	} else {
// 		fmt.Printf("No handler for method: %s\n", req.Method)
// 		r.NotFound(ctx)
// 	}
// }

// func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
// 	ctx := r.pool.Get().(*Context)
// 	ctx.Reset(w, req)
// 	defer r.pool.Put(ctx)

// 	// Ensure router is optimized
// 	if !r.optimized {
// 		r.Optimize()
// 	}

// 	// Run must-run middleware first
// 	for _, mw := range r.mustMiddleware {
// 		if mw(ctx) == Abort {
// 			return
// 		}
// 	}

// 	// Run regular middleware chain
// 	for _, mw := range r.middleware {
// 		if !mw(ctx) {
// 			return
// 		}
// 	}

// 	fmt.Println("middleware chain done")
// 	rootNode := r.tree
// 	for rootNode != nil {
// 		// fmt.Println("RootNode", rootNode.id, rootNode.segment, rootNode.path)
// 		if len(rootNode.children) > 0 {
// 			rootNode = rootNode.children[0]
// 		} else {
// 			break
// 		}
// 	}

// 	// Find route
// 	node, params := r.findRoute(req.URL.Path)

// 	if node == nil {
// 		r.NotFound(ctx)
// 		return
// 	}

// 	// Set parameters
// 	ctx.params = params

// 	// Execute handler
// 	if handler, ok := node.handlers[req.Method]; ok {
// 		handler(ctx)
// 	} else {
// 		r.NotFound(ctx)
// 	}
// }

// FindRoute with caching
// func (r *Router) findRoute(path string) (*node, *Params) {
// 	// Check cache first
// 	// Normal route finding
// 	params := NewParams(10)
// 	node := r.tree.findRoute(path, params)

// 	// Cache the result
// 	return node, params
// }

// func (n *node) findRoute(path string, params *Params) *node {
// 	fmt.Printf("Finding route for path: %s\n", path)

// 	// Special handling for root path
// 	if path == "/" || path == "" {
// 		if len(n.handlers) > 0 {
// 			fmt.Println("Found root handler")
// 			return n
// 		}
// 		return nil
// 	}

// 	segments := strings.Split(strings.TrimPrefix(strings.TrimSuffix(path, "/"), "/"), "/")
// 	currentNode := n

// 	for i := 0; i < len(segments); i++ {
// 		segment := segments[i]
// 		fmt.Printf("Matching segment: %s\n", segment)

// 		found := false

// 		// First try exact match
// 		for _, child := range currentNode.children {
// 			if child.nodeType == staticNode && child.path == segment {
// 				currentNode = child
// 				found = true
// 				fmt.Printf("Found static match: %s\n", child.path)
// 				break
// 			}
// 		}

// 		// If no exact match, try parameter match
// 		if !found {
// 			for _, child := range currentNode.children {
// 				if child.nodeType == paramNode {
// 					params.Add(child.paramName, segment)
// 					currentNode = child
// 					found = true
// 					fmt.Printf("Found param match: %s\n", child.path)
// 					break
// 				}
// 			}
// 		}

// 		// If still no match, try catch-all
// 		if !found {
// 			for _, child := range currentNode.children {
// 				if child.nodeType == catchAllNode {
// 					remainingPath := strings.Join(segments[i:], "/")
// 					params.Add(child.paramName, remainingPath)
// 					return child
// 				}
// 			}
// 			return nil
// 		}
// 	}

// 	if len(currentNode.handlers) > 0 {
// 		fmt.Printf("Found handler at node: %s\n", currentNode.path)
// 		return currentNode
// 	}

// 	return nil
// }

// // findRoute locates the appropriate route in the tree
// func (n *node) findRoute(path string, params *Params) *node {

// 	// Handle root path
// 	if path == "/" && len(n.handlers) > 0 {
// 		fmt.Println("Found root handler")
// 		return n
// 	}

// 	// Split path into segments
// 	segments := strings.Split(strings.Trim(path, "/"), "/")
// 	currentNode := n

// 	for i := 0; i < len(segments); i++ {
// 		segment := segments[i]
// 		if segment == "" {
// 			continue
// 		}

// 		fmt.Printf("Processing segment: %s\n", segment)
// 		// Try to find static child first
// 		child := currentNode.getStaticChild(segment)
// 		if child != nil {
// 			fmt.Println("Found static child", child.segment)
// 		}

// 		// If no static child found, try parameter nodes
// 		if child == nil {
// 			child = currentNode.getParamChild()
// 			if child != nil {
// 				fmt.Printf("Found param child: %s\n", child.path)
// 				// Extract parameter value
// 				if params != nil {
// 					params.Add(child.paramName, segment)
// 				}
// 			}
// 		}

// 		// If still no child found, try catch-all
// 		if child == nil {
// 			child = currentNode.getCatchAllChild()
// 			if child != nil {
// 				fmt.Printf("Found catch-all child: %s\n", child.path)
// 				// Extract remaining path as catch-all value
// 				if params != nil {
// 					remainingPath := strings.Join(segments[i:], "/")
// 					params.Add(child.paramName, remainingPath)
// 				}
// 				return child
// 			}
// 			fmt.Println("No matching child found")
// 			return nil
// 		}

// 		currentNode = child
// 	}

// 	// Check if we found a handler
// 	if len(currentNode.handlers) > 0 {
// 		fmt.Printf("Found handlers at node: %s\n", currentNode.path)
// 		return currentNode
// 	}

// 	fmt.Println("No handlers found at final node")
// 	return nil
// }

// // findRoute finds a route in the tree
// func (r *Router) findRoute(path string) (*node, *Params) {
// 	if path == "/" {
// 		return r.tree, nil
// 	}

// 	segments := strings.Split(strings.Trim(path, "/"), "/")
// 	current := r.tree
// 	params := NewParams(10)

// 	for _, segment := range segments {
// 		found := false

// 		for _, child := range current.children {
// 			if child.path == segment || child.isParam {
// 				if child.isParam {
// 					params.Add(child.paramName, segment)
// 				}
// 				current = child
// 				found = true
// 				break
// 			}
// 		}

// 		if !found {
// 			return nil, nil
// 		}
// 	}

// 	return current, params
// }

// func main() {
//     router := NewRouter()

//     // Named routes
//     router.Get("/users/{id}", userHandler).Name("users.show")
//     router.Get("/users/{id}/posts/{post}", postHandler).Name("users.posts.show")

//     // Named routes in groups
//     admin := router.Group("/admin").Name("admin") // Group prefix name
//     admin.Get("/dashboard", dashboardHandler).Name("dashboard")
//     admin.Get("/users", adminUsersHandler).Name("users")

//     // API group with nested names
//     api := router.Group("/api").Name("api")
//     api.Get("/products/{id}", productHandler).Name("products.show")
//     api.Get("/categories/{id}", categoryHandler).Name("categories.show")

//     // Example handler that generates URLs
//     router.Get("/links", func(c *Context) {
//         // Generate URL for user profile
//         userURL, err := c.BuildURL("users.show", map[string]string{
//             "id": "123",
//         })
//         if err != nil {
//             http.Error(c.ResponseWriter, err.Error(), http.StatusInternalServerError)
//             return
//         }

//         // Generate URL for user post
//         postURL, err := c.BuildURL("users.posts.show", map[string]string{
//             "id":   "123",
//             "post": "456",
//         })
//         if err != nil {
//             http.Error(c.ResponseWriter, err.Error(), http.StatusInternalServerError)
//             return
//         }

//         // Generate URL for admin dashboard
//         adminURL, err := c.BuildURL("admin.dashboard", nil)
//         if err != nil {
//             http.Error(c.ResponseWriter, err.Error(), http.StatusInternalServerError)
//             return
//         }

//         fmt.Fprintf(c.ResponseWriter, "User Profile: %s\n", userURL)
//         fmt.Fprintf(c.ResponseWriter, "User Post: %s\n", postURL)
//         fmt.Fprintf(c.ResponseWriter, "Admin Dashboard: %s\n", adminURL)
//     })

//     log.Fatal(http.ListenAndServe(":8080", router))
// }

// // Handler examples
// func userHandler(c *Context) {
//     id := c.Param("id")
//     fmt.Fprintf(c.ResponseWriter, "User ID: %s", id)
// }

// func postHandler(c *Context) {
//     userId := c.Param("id")
//     postId := c.Param("post")
//     fmt.Fprintf(c.ResponseWriter, "User ID: %s, Post ID: %s", userId, postId)
// }

// func dashboardHandler(c *Context) {
//     fmt.Fprintf(c.ResponseWriter, "Admin Dashboard")
// }

// // Example middleware that uses named routes
// func RedirectMiddleware(c *Context) bool {
//     if shouldRedirect(c) {
//         loginURL, err := c.BuildURL("auth.login", nil)
//         if err == nil {
//             http.Redirect(c.ResponseWriter, c.Request, loginURL, http.StatusFound)
//             return false
//         }
//     }
//     return true
// }

// // Helper function to generate URLs in your application
// func generateLinks(router *Router) {
//     // Generate URL for user profile
//     userURL, _ := router.URL("users.show", map[string]string{
//         "id": "123",
//     })
//     fmt.Printf("User Profile URL: %s\n", userURL)

//     // Generate URL for admin dashboard
//     adminURL, _ := router.URL("admin.dashboard", nil)
//     fmt.Printf("Admin Dashboard URL: %s\n", adminURL)
// }

// Add these new types and fields to existing types
// type (
// 	// RouteInfo stores information about a named route
// 	RouteInfo struct {
// 		path       string
// 		params     []string // stores parameter names
// 		isWildcard bool
// 	}

// 	// Router struct with added namedRoutes
// 	Router struct {
// 		tree        *node
// 		pool        sync.Pool
// 		middleware  []middlewareEntry
// 		namedRoutes map[string]RouteInfo // stores named routes
// 	}

// 	// Route struct with added name field
// 	Route struct {
// 		prefix     string
// 		router     *Router
// 		middleware []middlewareEntry
// 		name       string // current route name prefix
// 	}
// )

// // NewRouter updated to initialize namedRoutes
// func NewRouter() *Router {
// 	r := &Router{
// 		tree: &node{
// 			path:     "/",
// 			handlers: make(map[string][]Handler),
// 		},
// 		namedRoutes: make(map[string]RouteInfo),
// 	}

// 	r.pool.New = func() interface{} {
// 		return &Context{
// 			params: make(map[string]string),
// 			store:  make(map[string]interface{}),
// 		}
// 	}

// 	return r
// }

// // Name sets the name for a route

// // Add method modified to store last path
// func (r *Router) Add(method, path string, handlers ...Handler) {
// 	r.lastPath = path
// 	// ... rest of the Add implementation
// }

// package main

// import (
//     "fmt"
//     "log"
//     "net/http"
// )

// Add these new types and fields
// type (
//     // CORSConfig holds CORS configuration
//     CORSConfig struct {
//         AllowOrigins     []string
//         AllowMethods     []string
//         AllowHeaders     []string
//         ExposeHeaders    []string
//         AllowCredentials bool
//         MaxAge          int // in seconds
//     }

//     // Router with added CORS configuration
//     Router struct {
//         tree              *node
//         pool              sync.Pool
//         middleware        []middlewareEntry
//         namedRoutes       map[string]RouteInfo
//         errorHandlers     map[int]ErrorHandler
//         errorHandler      ErrorHandler
//         panicHandler      ErrorHandler
//         notFoundHandler   Handler
//         methodNotAllowed  Handler
//         corsConfig        *CORSConfig
//         automaticOPTIONS  bool // flag to enable/disable automatic OPTIONS handling
//     }
// )

// // Default CORS configuration
// var defaultCORSConfig = &CORSConfig{
//     AllowOrigins:     []string{"*"},
//     AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"},
//     AllowHeaders:     []string{"Origin", "Content-Length", "Content-Type", "Authorization"},
//     ExposeHeaders:    []string{},
//     AllowCredentials: false,
//     MaxAge:          86400, // 24 hours
// }

// // NewRouter updated to initialize CORS
// func NewRouter() *Router {
//     r := &Router{
//         tree: &node{
//             path:     "/",
//             handlers: make(map[string][]Handler),
//         },
//         namedRoutes:      make(map[string]RouteInfo),
//         errorHandlers:    make(map[int]ErrorHandler),
//         automaticOPTIONS: true,           // Enable by default
//         corsConfig:       defaultCORSConfig, // Use default CORS config
//     }

//     // ... rest of initialization
//     return r
// }

// // EnableAutomaticOPTIONS enables or disables automatic OPTIONS handling
// func (r *Router) EnableAutomaticOPTIONS(enable bool) {
//     r.automaticOPTIONS = enable
// }

// // SetCORSConfig sets custom CORS configuration
// func (r *Router) SetCORSConfig(config *CORSConfig) {
//     r.corsConfig = config
// }

// // getAllowedMethods returns all methods allowed for a path
// func (r *Router) getAllowedMethods(path string) []string {
//     node, _ := r.findRoute(path)
//     if node == nil {
//         return nil
//     }

//     methods := make([]string, 0)
//     for method := range node.handlers {
//         methods = append(methods, method)
//     }
//     return methods
// }

// // handleCORS handles CORS headers
// func (r *Router) handleCORS(c *Context) {
//     if r.corsConfig == nil {
//         return
//     }

//     origin := c.Request.Header.Get("Origin")
//     if origin == "" {
//         return
//     }

//     // Check if origin is allowed
//     allowOrigin := "*"
//     if len(r.corsConfig.AllowOrigins) > 0 && r.corsConfig.AllowOrigins[0] != "*" {
//         allowOrigin = ""
//         for _, o := range r.corsConfig.AllowOrigins {
//             if o == origin {
//                 allowOrigin = origin
//                 break
//             }
//         }
//         if allowOrigin == "" {
//             return
//         }
//     }

//     header := c.ResponseWriter.Header()
//     header.Set("Access-Control-Allow-Origin", allowOrigin)

//     if r.corsConfig.AllowCredentials {
//         header.Set("Access-Control-Allow-Credentials", "true")
//     }

//     if c.Request.Method == http.MethodOptions {
//         // Handle preflight request
//         if r.corsConfig.MaxAge > 0 {
//             header.Set("Access-Control-Max-Age", string(r.corsConfig.MaxAge))
//         }

//         // Get allowed methods for this path
//         methods := r.getAllowedMethods(c.Request.URL.Path)
//         if len(methods) > 0 {
//             header.Set("Access-Control-Allow-Methods", strings.Join(methods, ", "))
//         } else if len(r.corsConfig.AllowMethods) > 0 {
//             header.Set("Access-Control-Allow-Methods", strings.Join(r.corsConfig.AllowMethods, ", "))
//         }

//         // Handle Allow-Headers
//         reqHeaders := c.Request.Header.Get("Access-Control-Request-Headers")
//         if reqHeaders != "" {
//             header.Set("Access-Control-Allow-Headers", reqHeaders)
//         } else if len(r.corsConfig.AllowHeaders) > 0 {
//             header.Set("Access-Control-Allow-Headers", strings.Join(r.corsConfig.AllowHeaders, ", "))
//         }
//     } else if len(r.corsConfig.ExposeHeaders) > 0 {
//         // Handle simple request
//         header.Set("Access-Control-Expose-Headers", strings.Join(r.corsConfig.ExposeHeaders, ", "))
//     }
// }

// // Update ServeHTTP to handle OPTIONS and CORS
// func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
//     ctx := r.pool.Get().(*Context)
//     ctx.Reset(w, req)
//     defer r.pool.Put(ctx)

//     // Handle CORS
//     r.handleCORS(ctx)

//     // Handle OPTIONS request
//     if r.automaticOPTIONS && req.Method == http.MethodOptions {
//         if r.corsConfig != nil {
//             // CORS headers are already set by handleCORS
//             w.WriteHeader(http.StatusNoContent)
//             return
//         }
//     }

//     // ... rest of ServeHTTP implementation
// }

// package main

// import (
//     "fmt"
//     "log"
//     "net/http"
// )

// func main() {
//     router := NewRouter()

//     // Custom CORS configuration
//     router.SetCORSConfig(&CORSConfig{
//         AllowOrigins:     []string{"http://localhost:3000", "https://example.com"},
//         AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "PATCH"},
//         AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
//         ExposeHeaders:    []string{"Content-Length"},
//         AllowCredentials: true,
//         MaxAge:          3600,
//     })

//     // Routes
//     router.Get("/api/users", func(c *Context) {
//         fmt.Fprintf(c.ResponseWriter, "List of users")
//     })

//     router.Post("/api/users", func(c *Context) {
//         fmt.Fprintf(c.ResponseWriter, "Create user")
//     })

//     // Group with specific CORS configuration
//     api := router.Group("/api/v2")
//     api.Use(func(c *Context) bool {
//         // Custom CORS handling for this group
//         c.ResponseWriter.Header().Set("Access-Control-Allow-Origin", "https://api.example.com")
//         return true
//     })

//     log.Fatal(http.ListenAndServe(":8080", router))
// }

// //example
// func main() {
//     router := NewRouter()

//     // Configure CORS using helper methods
//     router.AllowOrigin("http://localhost:3000", "https://example.com")
//     router.AllowMethods("GET", "POST", "PUT", "DELETE")
//     router.AllowHeaders("Content-Type", "Authorization")
//     router.ExposeHeaders("Content-Length")
//     router.AllowCredentials(true)
//     router.SetMaxAge(3600)

//     // Development helper
//     router.EnableDevelopmentCORS := func(r *Router) {
//         r.SetCORSConfig(&CORSConfig{
//             AllowOrigins:     []string{"*"},
//             AllowMethods:     []string{"*"},
//             AllowHeaders:     []string{"*"},
//             AllowCredentials: true,
//             MaxAge:          86400,
//         })
//     }
// }

// func main() {
// 	router := NewRouter()

// 	// Configure path handling
// 	router.SetPathConfig(PathConfig{
// 		CleanPath:              true,
// 		RemoveTrailingSlash:    false,
// 		RedirectTrailingSlash:  true,
// 		RedirectFixedPath:      true,
// 		HandleMethodNotAllowed: true,
// 		CaseInsensitive:        true,
// 	})

// 	// These routes will be normalized automatically
// 	router.Get("/users//..//profile//", func(c *Context) {
// 		fmt.Fprintf(c.ResponseWriter, "Profile page")
// 	})

// 	router.Get("/USERS/PROFILE", func(c *Context) {
// 		fmt.Fprintf(c.ResponseWriter, "Profile page (case insensitive)")
// 	})

// 	// Examples of how paths will be normalized:
// 	// /users/../profile    -> /profile
// 	// /users//profile     -> /users/profile
// 	// /users/./profile    -> /users/profile
// 	// /users/profile/     -> /users/profile/ (or /users/profile depending on config)
// 	// /USERS/PROFILE     -> /users/profile (if case insensitive)

// 	log.Fatal(http.ListenAndServe(":8080", router))
// }

// func main() {
//     router := NewRouter()
//     pathUtils := router.Path()

//     // Using path utilities
//     cleanPath := pathUtils.Clean("/users/../profile/")
//     segments := pathUtils.Split("/users/profile/settings")
//     basePath := pathUtils.Base("/users/profile")
//     dirPath := pathUtils.Dir("/users/profile")

//     // Route group with path utilities
//     api := router.Group(pathUtils.Join("/api", "v1"))
//     api.Get(pathUtils.Join("users", "{id}"), func(c *Context) {
//         fmt.Fprintf(c.ResponseWriter, "User ID: %s", c.Param("id"))
//     })
// }
/*
	This implementation provides:

Path cleaning and normalization
Handling of dot segments (. and ..)
Duplicate slash removal
Trailing slash configuration
Case sensitivity configuration
Path validation
Automatic redirects for cleaned paths
Query string preservation
Path utility functions
Configuration options
Features of the path handling:

Security through path validation
Consistent path format
Configurable behavior
Automatic redirects
Case sensitivity options
Trailing slash handling
Path joining utilities
Path splitting utilities
Directory/base path handling
Path validation helpers
This makes the router more robust and secure while providing consistent URL handling across the application. It also helps prevent common security issues related to path traversal and malformed URLs.
*/

// // Add registers a route - optimized path handling
// func (r *Router) Add(method, path string, handler Handler) {
// 	if path == "/" {
// 		r.tree.handler[method] = handler
// 		return
// 	}

// 	current := r.tree
// 	segments := splitPath(path) // custom split function

// 	for _, segment := range segments {
// 		isParam := segment[0] == '{' && segment[len(segment)-1] == '}'

// 		child := current.findChild(segment)
// 		if child == nil {
// 			child = &node{
// 				path:    segment,
// 				handler: make(map[string]Handler),
// 			}
// 			if isParam {
// 				child.param = segment[1 : len(segment)-1]
// 			}
// 			current.children = append(current.children, child)
// 		}
// 		current = child
// 	}
// 	current.handler[method] = handler
// }

// // ServeHTTP - optimized request handling
// func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
// 	ctx := r.pool.Get().(*Context)
// 	ctx.Reset(w, req)
// 	defer r.pool.Put(ctx)

// 	// Panic recovery
// 	defer func() {
// 		if err := recover(); err != nil {
// 			if r.panicHandler != nil {
// 				r.panicHandler(ctx, fmt.Errorf("panic: %v\n%s", err, debug.Stack()))
// 			} else {
// 				fmt.Println("Panic recovery Error (SERGE HTTP):", err)
// 				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
// 			}
// 		}
// 	}()

// 	// Fast path for middleware
// 	for i := 0; i < len(r.middleware); i++ {
// 		if !r.middleware[i](ctx) {
// 			return
// 		}
// 	}

// 	// Find route
// 	current := r.tree
// 	path := req.URL.Path
// 	if path == "/" {
// 		if h := current.handler[req.Method]; h != nil {
// 			h(ctx)
// 			return
// 		}

// 		if r.methodNotAllowed != nil {
// 			r.methodNotAllowed(ctx)
// 		} else {
// 			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
// 		}
// 		return
// 	}

// 	segments := splitPath(path)
// 	for i, segment := range segments {
// 		found := false
// 		for _, child := range current.children {
// 			if child.path == segment || child.param != "" {
// 				if child.param != "" && ctx.pCount < 8 {
// 					ctx.params[ctx.pCount].key = child.param
// 					ctx.params[ctx.pCount].value = segment
// 					ctx.pCount++
// 				}
// 				current = child
// 				found = true
// 				break
// 			}
// 		}

// 		if !found {
// 			r.handleError(ctx, errors.New("Route not found:"+path))
// 			return
// 		}

// 		if i == len(segments)-1 {
// 			if h := current.handler[req.Method]; h != nil {
// 				h(ctx)
// 			} else {
// 				r.NotFound(ctx)
// 			}
// 		}

// 		// Fast path for must middleware
// 		for i := 0; i < len(r.mustMiddleware); i++ {
// 			r.mustMiddleware[i](ctx)
// 			if ctx.signaltype == Abort {
// 				return
// 			}
// 		}
// 	}
// }

// // Example usage
// func main() {
//     router := NewRouter()

//     // Configure WebSocket
//     router.WebSocket("/ws", WebSocketConfig{
//         HandshakeTimeout: 10 * time.Second,
//         ReadBufferSize:   1024,
//         WriteBufferSize:  1024,
//         AllowedOrigins:   []string{"*"},
//         PingInterval:     30 * time.Second,
//         PongWait:         60 * time.Second,
//         WriteWait:        10 * time.Second,
//         MaxMessageSize:   512 * 1024, // 512KB
//     })

//     // Start server with hot reload
//     server := NewGracefulServer(router)
//     server.Run()
// }

// package airouterv3

// import (
//     "encoding/json"
//     "errors"
//     "github.com/gorilla/websocket"
//     "net/http"
//     "sync"
//     "time"
// )

// // WebSocket types
// type (
//     // Connection represents a WebSocket connection
//     Connection struct {
//         conn      *websocket.Conn
//         hub       *Hub
//         send      chan []byte
//         rooms     map[string]bool
//         userID    string
//         metadata  map[string]interface{}
//         mu        sync.RWMutex
//     }

//     // Hub maintains the set of active connections
//     Hub struct {
//         // Registered connections
//         connections map[*Connection]bool

//         // Rooms for broadcasting
//         rooms map[string]map[*Connection]bool

//         // Inbound messages from the connections
//         broadcast chan *Message

//         // Register requests from the connections
//         register chan *Connection

//         // Unregister requests from connections
//         unregister chan *Connection

//         // Mutex for thread-safe operations
//         mu sync.RWMutex

//         // Metrics
//         metrics *WebSocketMetrics
//     }

//     // Message represents a WebSocket message
//     Message struct {
//         Type    string      `json:"type"`
//         Room    string      `json:"room,omitempty"`
//         Data    interface{} `json:"data"`
//         UserID  string      `json:"userId,omitempty"`
//     }

//     // WebSocketMetrics tracks WebSocket-specific metrics
//     WebSocketMetrics struct {
//         activeConnections    prometheus.Gauge
//         messagesReceived    prometheus.Counter
//         messagesSent        prometheus.Counter
//         bytesReceived      prometheus.Counter
//         bytesSent          prometheus.Counter
//         errors             prometheus.Counter
//     }
// )

// // NewHub creates a new Hub instance
// func NewHub() *Hub {
//     return &Hub{
//         broadcast:   make(chan *Message),
//         register:    make(chan *Connection),
//         unregister:  make(chan *Connection),
//         connections: make(map[*Connection]bool),
//         rooms:      make(map[string]map[*Connection]bool),
//         metrics:    newWebSocketMetrics(),
//     }
// }

// // Run starts the Hub
// func (h *Hub) Run() {
//     for {
//         select {
//         case conn := <-h.register:
//             h.registerConnection(conn)
//         case conn := <-h.unregister:
//             h.unregisterConnection(conn)
//         case message := <-h.broadcast:
//             h.broadcastMessage(message)
//         }
//     }
// }

// // Connection methods
// func (c *Connection) readPump() {
//     defer func() {
//         c.hub.unregister <- c
//         c.conn.Close()
//     }()

//     c.conn.SetReadLimit(maxMessageSize)
//     c.conn.SetReadDeadline(time.Now().Add(pongWait))
//     c.conn.SetPongHandler(func(string) error {
//         c.conn.SetReadDeadline(time.Now().Add(pongWait))
//         return nil
//     })

//     for {
//         _, message, err := c.conn.ReadMessage()
//         if err != nil {
//             if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
//                 c.hub.metrics.errors.Inc()
//             }
//             break
//         }

//         c.hub.metrics.messagesReceived.Inc()
//         c.hub.metrics.bytesReceived.Add(float64(len(message)))

//         var msg Message
//         if err := json.Unmarshal(message, &msg); err != nil {
//             continue
//         }

//         // Handle different message types
//         switch msg.Type {
//         case "join":
//             c.joinRoom(msg.Room)
//         case "leave":
//             c.leaveRoom(msg.Room)
//         case "message":
//             c.hub.broadcast <- &msg
//         }
//     }
// }

// func (c *Connection) writePump() {
//     ticker := time.NewTicker(pingPeriod)
//     defer func() {
//         ticker.Stop()
//         c.conn.Close()
//     }()

//     for {
//         select {
//         case message, ok := <-c.send:
//             c.conn.SetWriteDeadline(time.Now().Add(writeWait))
//             if !ok {
//                 c.conn.WriteMessage(websocket.CloseMessage, []byte{})
//                 return
//             }

//             w, err := c.conn.NextWriter(websocket.TextMessage)
//             if err != nil {
//                 return
//             }
//             w.Write(message)

//             c.hub.metrics.messagesSent.Inc()
//             c.hub.metrics.bytesSent.Add(float64(len(message)))

//             if err := w.Close(); err != nil {
//                 return
//             }
//         case <-ticker.C:
//             c.conn.SetWriteDeadline(time.Now().Add(writeWait))
//             if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
//                 return
//             }
//         }
//     }
// }

// // Room management methods
// func (c *Connection) joinRoom(room string) {
//     c.hub.mu.Lock()
//     defer c.hub.mu.Unlock()

//     if _, ok := c.hub.rooms[room]; !ok {
//         c.hub.rooms[room] = make(map[*Connection]bool)
//     }
//     c.hub.rooms[room][c] = true
//     c.rooms[room] = true
// }

// func (c *Connection) leaveRoom(room string) {
//     c.hub.mu.Lock()
//     defer c.hub.mu.Unlock()

//     if _, ok := c.hub.rooms[room]; ok {
//         delete(c.hub.rooms[room], c)
//         delete(c.rooms, room)
//     }
// }

// // Hub helper methods
// func (h *Hub) registerConnection(conn *Connection) {
//     h.mu.Lock()
//     defer h.mu.Unlock()

//     h.connections[conn] = true
//     h.metrics.activeConnections.Inc()
// }

// func (h *Hub) unregisterConnection(conn *Connection) {
//     h.mu.Lock()
//     defer h.mu.Unlock()

//     if _, ok := h.connections[conn]; ok {
//         delete(h.connections, conn)
//         close(conn.send)

//         // Remove from all rooms
//         for room := range conn.rooms {
//             delete(h.rooms[room], conn)
//         }

//         h.metrics.activeConnections.Dec()
//     }
// }

// func (h *Hub) broadcastMessage(msg *Message) {
//     h.mu.RLock()
//     defer h.mu.RUnlock()

//     if msg.Room != "" {
//         // Broadcast to specific room
//         if connections, ok := h.rooms[msg.Room]; ok {
//             for conn := range connections {
//                 select {
//                 case conn.send <- msg.Data.([]byte):
//                 default:
//                     close(conn.send)
//                     delete(h.connections, conn)
//                 }
//             }
//         }
//     } else {
//         // Broadcast to all connections
//         for conn := range h.connections {
//             select {
//             case conn.send <- msg.Data.([]byte):
//             default:
//                 close(conn.send)
//                 delete(h.connections, conn)
//             }
//         }
//     }
// }

// // Usage example
// func main() {
//     router := NewRouter()
//     hub := NewHub()
//     go hub.Run()

//     router.WebSocket("/ws", func(c *Context, conn *Connection) {
//         // Set up connection
//         conn.userID = c.Query("user_id")
//         conn.metadata["user_agent"] = c.Request.UserAgent()

//         // Send welcome message
//         welcome := Message{
//             Type: "welcome",
//             Data: "Welcome to the chat!",
//         }
//         welcomeJSON, _ := json.Marshal(welcome)
//         conn.send <- welcomeJSON
//     })

//     // Chat room example
//     router.WebSocket("/ws/chat/{room}", func(c *Context, conn *Connection) {
//         room := c.Param("room")
//         conn.joinRoom(room)

//         // Notify room about new user
//         join := Message{
//             Type: "user_joined",
//             Room: room,
//             Data: conn.userID,
//         }
//         joinJSON, _ := json.Marshal(join)
//         conn.hub.broadcast <- &Message{
//             Type: "message",
//             Room: room,
//             Data: joinJSON,
//         }
//     })
// }

// func main() {
//     router := NewRouter()
//     hub := NewHub()
//     go hub.Run()

//     // Authentication middleware
//     auth := WebSocketAuth(func(r *http.Request) bool {
//         return r.Header.Get("Authorization") != ""
//     })

//     // Rate limiting middleware
//     rateLimit := WebSocketRateLimit(100, time.Minute)

//     // Chat application
//     router.WebSocket("/ws/chat", auth, func(c *Context, conn *Connection) {
//         conn.Use(func(conn *Connection, msg []byte) bool {
//             return rateLimit(conn)
//         })

//         // Handle different message types
//         var msg Message
//         if err := json.Unmarshal(msg, &msg); err != nil {
//             return false
//         }

//         switch msg.Type {
//         case "chat":
//             // Broadcast to room
//             conn.hub.broadcast <- &msg
//         case "private":
//             // Send private message
//             if target, ok := conn.hub.connections[msg.UserID]; ok {
//                 target.send <- msg.Data.([]byte)
//             }
//         }

//         return true
//     })

//     // Room management
//     router.Get("/api/rooms", func(c *Context) {
//         rooms := make([]string, 0, len(hub.rooms))
//         for room := range hub.rooms {
//             rooms = append(rooms, room)
//         }
//         c.JSON(200, rooms)
//     })

//     router.Get("/api/rooms/{room}/users", func(c *Context) {
//         room := c.Param("room")
//         if connections, ok := hub.rooms[room]; ok {
//             users := make([]string, 0, len(connections))
//             for conn := range connections {
//                 users = append(users, conn.userID)
//             }
//             c.JSON(200, users)
//         } else {
//             c.JSON(404, map[string]string{"error": "Room not found"})
//         }
//     })
// }

//Rate limiting
// package router

// import (
//     "sync"
//     "time"
// )

// // Rate limiting types and constants
// type (
//     // RateLimiterConfig holds rate limiting configuration
//     RateLimiterConfig struct {
//         // Connection limits
//         MaxConnections        int           // Maximum concurrent connections
//         ConnectionRate       int           // New connections per interval
//         ConnectionInterval   time.Duration // Interval for connection rate

//         // Message limits
//         MessageRate         int           // Messages per interval
//         MessageInterval     time.Duration // Interval for message rate
//         BurstSize          int           // Maximum burst size

//         // Room limits
//         MaxRoomsPerUser     int           // Maximum rooms per user
//         MaxUsersPerRoom     int           // Maximum users per room
//         RoomMessageRate     int           // Messages per room per interval
//         RoomInterval        time.Duration // Interval for room messages

//         // Bandwidth limits
//         MaxMessageSize      int64         // Maximum message size in bytes
//         BandwidthRate      int64         // Bytes per interval
//         BandwidthInterval  time.Duration // Interval for bandwidth
//     }

//     // RateLimiter implements rate limiting logic
//     RateLimiter struct {
//         config    RateLimiterConfig
//         store     RateLimitStore
//         metrics   *RateLimitMetrics
//     }

//     // RateLimitStore interface for storing rate limit data
//     RateLimitStore interface {
//         Increment(key string, window time.Duration) (int, error)
//         Decrease(key string) error
//         Reset(key string) error
//         Get(key string) (int, error)
//     }

//     // TokenBucket implements token bucket algorithm
//     TokenBucket struct {
//         tokens    float64
//         capacity  float64
//         rate      float64
//         lastCheck time.Time
//         mu        sync.Mutex
//     }

//     // SlidingWindow implements sliding window rate limiting
//     SlidingWindow struct {
//         windows map[int64]int
//         size    time.Duration
//         limit   int
//         mu      sync.Mutex
//     }

//     // RateLimitMetrics tracks rate limiting metrics
//     RateLimitMetrics struct {
//         connectionLimits  prometheus.Counter
//         messageLimits    prometheus.Counter
//         roomLimits       prometheus.Counter
//         bandwidthLimits  prometheus.Counter
//     }
// )

// // Default configuration
// var DefaultRateLimiterConfig = RateLimiterConfig{
//     MaxConnections:      1000,
//     ConnectionRate:      10,
//     ConnectionInterval:  time.Second,
//     MessageRate:        100,
//     MessageInterval:    time.Second,
//     BurstSize:         20,
//     MaxRoomsPerUser:    10,
//     MaxUsersPerRoom:    100,
//     RoomMessageRate:    50,
//     RoomInterval:       time.Second,
//     MaxMessageSize:     64 * 1024, // 64KB
//     BandwidthRate:      1024 * 1024, // 1MB
//     BandwidthInterval:  time.Second,
// }

// // NewRateLimiter creates a new rate limiter
// func NewRateLimiter(config RateLimiterConfig) *RateLimiter {
//     return &RateLimiter{
//         config: config,
//         store:  NewRedisRateLimitStore(), // Or other store implementation
//         metrics: newRateLimitMetrics(),
//     }
// }

// // Token bucket implementation
// func NewTokenBucket(capacity float64, rate float64) *TokenBucket {
//     return &TokenBucket{
//         tokens:    capacity,
//         capacity:  capacity,
//         rate:     rate,
//         lastCheck: time.Now(),
//     }
// }

// func (tb *TokenBucket) Allow() bool {
//     tb.mu.Lock()
//     defer tb.mu.Unlock()

//     now := time.Now()
//     elapsed := now.Sub(tb.lastCheck).Seconds()
//     tb.tokens = math.Min(tb.capacity, tb.tokens+(elapsed*tb.rate))
//     tb.lastCheck = now

//     if tb.tokens >= 1 {
//         tb.tokens--
//         return true
//     }
//     return false
// }

// // Sliding window implementation
// func NewSlidingWindow(size time.Duration, limit int) *SlidingWindow {
//     return &SlidingWindow{
//         windows: make(map[int64]int),
//         size:   size,
//         limit:  limit,
//     }
// }

// func (sw *SlidingWindow) Allow() bool {
//     sw.mu.Lock()
//     defer sw.mu.Unlock()

//     now := time.Now().UnixNano()
//     windowStart := now - sw.size.Nanoseconds()

//     // Clean old windows
//     for timestamp := range sw.windows {
//         if timestamp < windowStart {
//             delete(sw.windows, timestamp)
//         }
//     }

//     // Count current window
//     total := 0
//     for _, count := range sw.windows {
//         total += count
//     }

//     if total >= sw.limit {
//         return false
//     }

//     sw.windows[now] = sw.windows[now] + 1
//     return true
// }

// // Rate limiter methods
// type RateLimiter struct {
//     config RateLimiterConfig
//     store  RateLimitStore

//     connectionLimiter *TokenBucket
//     messageLimiter   map[string]*SlidingWindow
//     roomLimiters     map[string]*TokenBucket
//     bandwidthLimiter *TokenBucket

//     mu sync.RWMutex
// }

// // Connection rate limiting
// func (rl *RateLimiter) AllowConnection(userID string) bool {
//     // Check max connections
//     if conns, _ := rl.store.Get("connections"); conns >= rl.config.MaxConnections {
//         rl.metrics.connectionLimits.Inc()
//         return false
//     }

//     // Check connection rate
//     if !rl.connectionLimiter.Allow() {
//         rl.metrics.connectionLimits.Inc()
//         return false
//     }

//     rl.store.Increment("connections", rl.config.ConnectionInterval)
//     return true
// }

// // Message rate limiting
// func (rl *RateLimiter) AllowMessage(userID string, size int64) bool {
//     rl.mu.RLock()
//     limiter, exists := rl.messageLimiter[userID]
//     rl.mu.RUnlock()

//     if !exists {
//         rl.mu.Lock()
//         limiter = NewSlidingWindow(rl.config.MessageInterval, rl.config.MessageRate)
//         rl.messageLimiter[userID] = limiter
//         rl.mu.Unlock()
//     }

//     // Check message rate
//     if !limiter.Allow() {
//         rl.metrics.messageLimits.Inc()
//         return false
//     }

//     // Check message size
//     if size > rl.config.MaxMessageSize {
//         rl.metrics.messageLimits.Inc()
//         return false
//     }

//     // Check bandwidth
//     if !rl.bandwidthLimiter.Allow() {
//         rl.metrics.bandwidthLimits.Inc()
//         return false
//     }

//     return true
// }

// // Room rate limiting
// func (rl *RateLimiter) AllowRoomAction(userID, room string, action string) bool {
//     switch action {
//     case "join":
//         // Check max rooms per user
//         userRooms, _ := rl.store.Get(fmt.Sprintf("user:%s:rooms", userID))
//         if userRooms >= rl.config.MaxRoomsPerUser {
//             rl.metrics.roomLimits.Inc()
//             return false
//         }

//         // Check max users per room
//         roomUsers, _ := rl.store.Get(fmt.Sprintf("room:%s:users", room))
//         if roomUsers >= rl.config.MaxUsersPerRoom {
//             rl.metrics.roomLimits.Inc()
//             return false
//         }

//     case "message":
//         rl.mu.RLock()
//         limiter, exists := rl.roomLimiters[room]
//         rl.mu.RUnlock()

//         if !exists {
//             rl.mu.Lock()
//             limiter = NewTokenBucket(float64(rl.config.RoomMessageRate),
//                 float64(rl.config.RoomMessageRate)/rl.config.RoomInterval.Seconds())
//             rl.roomLimiters[room] = limiter
//             rl.mu.Unlock()
//         }

//         if !limiter.Allow() {
//             rl.metrics.roomLimits.Inc()
//             return false
//         }
//     }

//     return true
// }

// // Integration with WebSocket connection
// func (conn *Connection) handleMessage(msg []byte) error {
//     // Check rate limits
//     if !conn.hub.rateLimiter.AllowMessage(conn.userID, int64(len(msg))) {
//         return errors.New("rate limit exceeded")
//     }

//     var message Message
//     if err := json.Unmarshal(msg, &message); err != nil {
//         return err
//     }

//     // Check room limits for room messages
//     if message.Room != "" {
//         if !conn.hub.rateLimiter.AllowRoomAction(conn.userID, message.Room, "message") {
//             return errors.New("room rate limit exceeded")
//         }
//     }

//     // Process message
//     conn.hub.broadcast <- &message
//     return nil
// }

// // Integration with Hub
// type Hub struct {
//     // ... existing fields ...
//     rateLimiter *RateLimiter
// }

// // // Usage example
// // func main() {
// //     router := NewRouter()

// //     // Configure rate limiter
// //     rateLimiter := NewRateLimiter(RateLimiterConfig{
// //         MaxConnections:     1000,
// //         ConnectionRate:     10,
// //         ConnectionInterval: time.Second,
// //         MessageRate:       100,
// //         MessageInterval:   time.Second,
// //         BurstSize:        20,
// //         MaxRoomsPerUser:   10,
// //         MaxUsersPerRoom:   100,
// //         RoomMessageRate:   50,
// //         RoomInterval:      time.Second,
// //         MaxMessageSize:    64 * 1024,
// //         BandwidthRate:     1024 * 1024,
// //         BandwidthInterval: time.Second,
// //     })

// //     hub := NewHub()
// //     hub.rateLimiter = rateLimiter
// //     go hub.Run()

// //     // WebSocket endpoint with rate limiting
// //     router.WebSocket("/ws", func(c *Context, conn *Connection) {
// //         // Connection is already rate limited by the hub

// //         // Set up message handling
// //         conn.onMessage = func(msg []byte) error {
// //             return conn.handleMessage(msg)
// //         }
// //     })
// // }

// //Hot reload
// package router

// import (
//     "encoding/json"
//     "github.com/gorilla/websocket"
//     "sync"
//     "time"
// )

// // Add authentication middleware
// func WebSocketAuth(authFunc func(*http.Request) bool) func(*Context) bool {
// 	return func(c *Context) bool {
// 		if !authFunc(c.Request) {
// 			c.ResponseWriter.WriteHeader(http.StatusUnauthorized)
// 			return false
// 		}
// 		return true
// 	}
// }

// // Add rate limiting
// func WebSocketRateLimit(limit int, window time.Duration) func(*Connection) bool {
// 	limiter := rate.NewLimiter(rate.Every(window/time.Duration(limit)), limit)
// 	return func(conn *Connection) bool {
// 		return limiter.Allow()
// 	}
// }

// // Rate limiting types and constants
// type (
// 	// RateLimiterConfig holds rate limiting configuration
// 	RateLimiterConfig struct {
// 		// Connection limits
// 		MaxConnections     int           // Maximum concurrent connections
// 		ConnectionRate     int           // New connections per interval
// 		ConnectionInterval time.Duration // Interval for connection rate

// 		// Message limits
// 		MessageRate     int           // Messages per interval
// 		MessageInterval time.Duration // Interval for message rate
// 		BurstSize       int           // Maximum burst size

// 		// Room limits
// 		MaxRoomsPerUser int           // Maximum rooms per user
// 		MaxUsersPerRoom int           // Maximum users per room
// 		RoomMessageRate int           // Messages per room per interval
// 		RoomInterval    time.Duration // Interval for room messages

// 		// Bandwidth limits
// 		MaxMessageSize    int64         // Maximum message size in bytes
// 		BandwidthRate     int64         // Bytes per interval
// 		BandwidthInterval time.Duration // Interval for bandwidth
// 	}

// 	// RateLimiter implements rate limiting logic
// 	// RateLimiter struct {
// 	// 	config  RateLimiterConfig
// 	// 	store   RateLimitStore
// 	// 	metrics *RateLimitMetrics
// 	// }

// 	// RateLimitStore interface for storing rate limit data
// 	RateLimitStore interface {
// 		Increment(key string, window time.Duration) (int, error)
// 		Decrease(key string) error
// 		Reset(key string) error
// 		Get(key string) (int, error)
// 	}

// 	// TokenBucket implements token bucket algorithm
// 	TokenBucket struct {
// 		tokens    float64
// 		capacity  float64
// 		rate      float64
// 		lastCheck time.Time
// 		mu        sync.Mutex
// 	}

// 	// SlidingWindow implements sliding window rate limiting
// 	SlidingWindow struct {
// 		windows map[int64]int
// 		size    time.Duration
// 		limit   int
// 		mu      sync.Mutex
// 	}
// )

// // Default configuration
// var DefaultRateLimiterConfig = RateLimiterConfig{
// 	MaxConnections:     1000,
// 	ConnectionRate:     10,
// 	ConnectionInterval: time.Second,
// 	MessageRate:        100,
// 	MessageInterval:    time.Second,
// 	BurstSize:          20,
// 	MaxRoomsPerUser:    10,
// 	MaxUsersPerRoom:    100,
// 	RoomMessageRate:    50,
// 	RoomInterval:       time.Second,
// 	MaxMessageSize:     64 * 1024,   // 64KB
// 	BandwidthRate:      1024 * 1024, // 1MB
// 	BandwidthInterval:  time.Second,
// }

// // NewRateLimiter creates a new rate limiter
// func NewRateLimiter(config RateLimiterConfig) *RateLimiter {
// 	return &RateLimiter{
// 		config: config,
// 		store:  nil, // NewRedisRateLimitStore(), // Or other store implementation
// 	}
// }

// // Token bucket implementation
// func NewTokenBucket(capacity float64, rate float64) *TokenBucket {
// 	return &TokenBucket{
// 		tokens:    capacity,
// 		capacity:  capacity,
// 		rate:      rate,
// 		lastCheck: time.Now(),
// 	}
// }

// func (tb *TokenBucket) Allow() bool {
// 	tb.mu.Lock()
// 	defer tb.mu.Unlock()

// 	now := time.Now()
// 	elapsed := now.Sub(tb.lastCheck).Seconds()
// 	tb.tokens = math.Min(tb.capacity, tb.tokens+(elapsed*tb.rate))
// 	tb.lastCheck = now

// 	if tb.tokens >= 1 {
// 		tb.tokens--
// 		return true
// 	}
// 	return false
// }

// // Sliding window implementation
// func NewSlidingWindow(size time.Duration, limit int) *SlidingWindow {
// 	return &SlidingWindow{
// 		windows: make(map[int64]int),
// 		size:    size,
// 		limit:   limit,
// 	}
// }

// func (sw *SlidingWindow) Allow() bool {
// 	sw.mu.Lock()
// 	defer sw.mu.Unlock()

// 	now := time.Now().UnixNano()
// 	windowStart := now - sw.size.Nanoseconds()

// 	// Clean old windows
// 	for timestamp := range sw.windows {
// 		if timestamp < windowStart {
// 			delete(sw.windows, timestamp)
// 		}
// 	}

// 	// Count current window
// 	total := 0
// 	for _, count := range sw.windows {
// 		total += count
// 	}

// 	if total >= sw.limit {
// 		return false
// 	}

// 	sw.windows[now] = sw.windows[now] + 1
// 	return true
// }

// // Rate limiter methods
// type RateLimiter struct {
// 	config RateLimiterConfig
// 	store  RateLimitStore

// 	connectionLimiter *TokenBucket
// 	messageLimiter    map[string]*SlidingWindow
// 	roomLimiters      map[string]*TokenBucket
// 	bandwidthLimiter  *TokenBucket

// 	mu sync.RWMutex
// }

// // Connection rate limiting
// func (rl *RateLimiter) AllowConnection(userID string) bool {
// 	return true
// 	// Check max connections
// 	if conns, _ := rl.store.Get("connections"); conns >= rl.config.MaxConnections {
// 		// rl.metrics.connectionLimits.Inc()
// 		return false
// 	}

// 	// Check connection rate
// 	if !rl.connectionLimiter.Allow() {
// 		// rl.metrics.connectionLimits.Inc()
// 		return false
// 	}

// 	rl.store.Increment("connections", rl.config.ConnectionInterval)
// 	return true
// }

// // Message rate limiting
// func (rl *RateLimiter) AllowMessage(userID string, size int64) bool {
// 	return true
// 	rl.mu.RLock()
// 	limiter, exists := rl.messageLimiter[userID]
// 	rl.mu.RUnlock()

// 	if !exists {
// 		rl.mu.Lock()
// 		limiter = NewSlidingWindow(rl.config.MessageInterval, rl.config.MessageRate)
// 		rl.messageLimiter[userID] = limiter
// 		rl.mu.Unlock()
// 	}

// 	// Check message rate
// 	if !limiter.Allow() {
// 		// rl.metrics.messageLimits.Inc()
// 		return false
// 	}

// 	// Check message size
// 	if size > rl.config.MaxMessageSize {
// 		// rl.metrics.messageLimits.Inc()
// 		return false
// 	}

// 	// Check bandwidth
// 	if !rl.bandwidthLimiter.Allow() {
// 		// rl.metrics.bandwidthLimits.Inc()
// 		return false
// 	}

// 	return true
// }

// // Room rate limiting
// func (rl *RateLimiter) AllowRoomAction(userID, room string, action string) bool {
// 	return true
// 	switch action {
// 	case "join":
// 		// Check max rooms per user
// 		userRooms, _ := rl.store.Get(fmt.Sprintf("user:%s:rooms", userID))
// 		if userRooms >= rl.config.MaxRoomsPerUser {
// 			// rl.metrics.roomLimits.Inc()
// 			return false
// 		}

// 		// Check max users per room
// 		roomUsers, _ := rl.store.Get(fmt.Sprintf("room:%s:users", room))
// 		if roomUsers >= rl.config.MaxUsersPerRoom {
// 			// rl.metrics.roomLimits.Inc()
// 			return false
// 		}

// 	case "message":
// 		rl.mu.RLock()
// 		limiter, exists := rl.roomLimiters[room]
// 		rl.mu.RUnlock()

// 		if !exists {
// 			rl.mu.Lock()
// 			limiter = NewTokenBucket(float64(rl.config.RoomMessageRate),
// 				float64(rl.config.RoomMessageRate)/rl.config.RoomInterval.Seconds())
// 			rl.roomLimiters[room] = limiter
// 			rl.mu.Unlock()
// 		}

// 		if !limiter.Allow() {
// 			// rl.metrics.roomLimits.Inc()
// 			return false
// 		}
// 	}

// 	return true
// }

// // Add room management helpers
// type Room struct {
// 	Name        string
// 	Connections map[*Connection]bool
// 	metadata    map[string]interface{}
// 	mu          sync.RWMutex
// }

// func (h *Hub) CreateRoom(name string) *Room {
// 	h.mu.Lock()
// 	defer h.mu.Unlock()

// 	room := &Room{
// 		Name:        name,
// 		Connections: make(map[*Connection]bool),
// 		metadata:    make(map[string]interface{}),
// 	}

// 	h.rooms[name] = room.Connections
// 	return room
// }
