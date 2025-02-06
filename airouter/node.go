package airouter

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// Node types
const (
	staticNode nodeType = iota
	paramNode
	catchAllNode
)

/*
// Extended node structure

	node struct {
		path       string
		nodeType   nodeType
		isParam    bool
		isCatchAll bool
		paramName  string
		paramDef   *ParamDefinition
		handlers   map[string][]Handler
		children   []*node
		parent     *node  // Added for tree reorganization
		priority   int    // Added for frequency-based optimization
		fullPath   string // Full path from root to this node
	}
*/
type (
	// node represents a router tree node
	node struct {
		router     *Router      // Reference to the router instance
		segment    string       // Path segment for this node
		nodeType   nodeType     // Type of node (static, param, catchAll)
		paramName  string       // Parameter name for param and catchAll nodes
		children   []*node      // Child nodes
		handler    Handler      // Handler function for this route
		middleware []Middleware // Middleware chain for this route
		fullPath   string       // Full path from root to this node
		route      *Route       // Route metadata
		parent     *node        // Parent node reference

		// Performance optimizations
		staticChild   map[string]*node // Quick lookup for static children
		paramChild    *node            // Quick reference to parameter child
		catchAllChild *node            // Quick reference to catch-all child

		// Metadata and statistics
		depth        int          // Depth in the tree
		priority     int          // Routing priority
		createdAt    time.Time    // Node creation time
		lastAccessed time.Time    // Last access time
		accessCount  atomic.Int64 // Access counter

		// Caching
		cache *nodeCache // Cache for frequently accessed data

		// Compression
		compressed bool    // Whether node chain is compressed
		chainNodes []*node // Nodes in a compressed chain

		// Validation
		constraints []Constraint // Parameter constraints

		// Pattern matching
		pattern string         // Route pattern for matching
		regex   *regexp.Regexp // Compiled regex for complex matching

		// Concurrency control
		mu sync.RWMutex // Mutex for thread safety

		// Debug information
		debugInfo *nodeDebug // Debug metadata

		path       string
		isParam    bool
		isCatchAll bool
		handlers   map[string][]Handler

		paramDef *ParamDefinition
	}

	// nodeType represents the type of router node
	nodeType int

	// nodeCache provides caching for frequent operations
	nodeCache struct {
		params      *sync.Pool         // Pool of parameter objects
		contexts    *sync.Pool         // Pool of context objects
		handlers    map[string]Handler // Cached handlers
		mu          sync.RWMutex       // Cache mutex
		maxSize     int                // Maximum cache size
		lastCleaned time.Time          // Last cache cleanup time
	}

	// Constraint defines parameter validation rules
	Constraint struct {
		Pattern   string            // Regex pattern
		Validator func(string) bool // Custom validator function
		Message   string            // Error message
	}

	// nodeDebug holds debugging information
	nodeDebug struct {
		id       string    // Unique node identifier
		created  time.Time // Creation timestamp
		modified time.Time // Last modification time
		hits     int64     // Number of times node was accessed
		matches  int64     // Number of successful matches
		misses   int64     // Number of failed matches
		errors   []error   // Recent errors
		traces   []string  // Debug traces
	}
)

// newNode creates a new router tree node
func newNode(router *Router, segment string, nType nodeType) *node {
	return &node{
		router:      router,
		segment:     segment,
		nodeType:    nType,
		children:    make([]*node, 0),
		staticChild: make(map[string]*node),
		createdAt:   time.Now(),
		cache:       newNodeCache(),
		debugInfo:   newNodeDebug(),
		constraints: make([]Constraint, 0),
	}
}

// newNodeCache creates a new node cache
func newNodeCache() *nodeCache {
	return &nodeCache{
		params: &sync.Pool{
			New: func() interface{} {
				return NewParams(2)
			},
		},
		contexts: &sync.Pool{
			New: func() interface{} {
				return Context{}
			},
		},
		handlers:    make(map[string]Handler),
		maxSize:     1000,
		lastCleaned: time.Now(),
	}
}

// newNodeDebug creates new debug info
func newNodeDebug() *nodeDebug {
	return &nodeDebug{
		id:      uuid.New().String(),
		created: time.Now(),
		traces:  make([]string, 0),
		errors:  make([]error, 0),
	}
}

// addChild adds a child node
func (n *node) addChild(child *node) {
	n.mu.Lock()
	defer n.mu.Unlock()

	child.parent = n
	child.depth = n.depth + 1
	n.children = append(n.children, child)

	// Update quick lookup references
	switch child.nodeType {
	case staticNode:
		n.staticChild[child.segment] = child
	case paramNode:
		n.paramChild = child
	case catchAllNode:
		n.catchAllChild = child
	}
}

// compress optimizes a chain of nodes
func (n *node) compress() {
	if n.compressed || len(n.children) != 1 {
		return
	}

	child := n.children[0]
	if child.nodeType != staticNode || len(child.children) != 1 {
		return
	}

	// Compress chain
	n.chainNodes = append(n.chainNodes, child)
	n.segment += "/" + child.segment
	n.children = child.children
	n.compressed = true

	// Update metadata
	n.updateMetadata()
}

// updateMetadata updates node metadata
func (n *node) updateMetadata() {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.debugInfo.modified = time.Now()
	n.lastAccessed = time.Now()
	n.accessCount.Add(1)
}

// matchSegment checks if a path segment matches this node
func (n *node) matchSegment(segment string) bool {
	switch n.nodeType {
	case staticNode:
		return segment == n.segment
	case paramNode:
		return n.validateParam(segment)
	case catchAllNode:
		return true
	}
	return false
}

// validateParam validates a parameter value against constraints
func (n *node) validateParam(value string) bool {
	for _, constraint := range n.constraints {
		if constraint.Pattern != "" {
			if matched, _ := regexp.MatchString(constraint.Pattern, value); !matched {
				return false
			}
		}
		if constraint.Validator != nil && !constraint.Validator(value) {
			return false
		}
	}
	return true
}

// cleanup performs node cleanup operations
func (n *node) cleanup() {
	n.mu.Lock()
	defer n.mu.Unlock()

	// Clear caches
	n.cache.handlers = make(map[string]Handler)
	n.cache.lastCleaned = time.Now()

	// Reset counters
	n.accessCount.Store(0)

	// Clean debug info
	n.debugInfo.errors = n.debugInfo.errors[:0]
	n.debugInfo.traces = n.debugInfo.traces[:0]

	// Recursively cleanup children
	for _, child := range n.children {
		child.cleanup()
	}
}

// String provides a string representation of the node
func (n *node) String() string {
	return fmt.Sprintf("Node{type=%v, segment=%s, path=%s, depth=%d, children=%d}",
		n.nodeType, n.segment, n.fullPath, n.depth, len(n.children))
}

// debug adds a debug trace
func (n *node) debug(format string, args ...interface{}) {
	if !n.router.config.Debug {
		return
	}

	trace := fmt.Sprintf(format, args...)
	n.debugInfo.traces = append(n.debugInfo.traces, trace)
}

// error records an error
func (n *node) error(err error) {
	if !n.router.config.Debug {
		return
	}

	n.debugInfo.errors = append(n.debugInfo.errors, err)
}

// optimize optimizes a single node and its children
func (n *node) optimize(config OptimizationConfig) *node {
	if n == nil {
		return nil
	}

	// Step 1: Merge common prefixes
	if config.MergeCommonPrefixes {
		n = n.mergeCommonPrefixes()
	}

	// Step 2: Sort children by priority
	if config.SortByPriority {
		n.sortChildren()
	}

	// Step 3: Compress chains
	if config.CompressChains {
		n = n.compressChain()
	}

	// Step 4: Remove empty nodes
	if config.RemoveEmptyNodes {
		n = n.removeEmptyNodes()
	}

	// Recursively optimize children
	for i, child := range n.children {
		n.children[i] = child.optimize(config)
	}

	return n
}

// mergeCommonPrefixes merges nodes with common prefixes
func (n *node) mergeCommonPrefixes() *node {
	if len(n.children) <= 1 {
		return n
	}

	// Group children by their first character
	prefixGroups := make(map[byte][]*node)
	for _, child := range n.children {
		if len(child.path) > 0 {
			prefixGroups[child.path[0]] = append(prefixGroups[child.path[0]], child)
		}
	}

	// Merge nodes with common prefixes
	var newChildren []*node
	for _, group := range prefixGroups {
		if len(group) == 1 {
			newChildren = append(newChildren, group[0])
			continue
		}

		// Find common prefix
		prefix := longestCommonPrefix(group)
		if prefix == "" {
			newChildren = append(newChildren, group...)
			continue
		}

		// Create merged node
		merged := &node{
			path:     prefix,
			nodeType: staticNode,
			handlers: make(map[string][]Handler),
			children: make([]*node, 0),
		}

		// Adjust children paths and add them to merged node
		for _, child := range group {
			child.path = child.path[len(prefix):]
			if child.path == "" && len(child.handlers) > 0 {
				merged.handlers = child.handlers
			} else if child.path != "" {
				merged.children = append(merged.children, child)
			}
		}

		newChildren = append(newChildren, merged)
	}

	n.children = newChildren
	return n
}

// sortChildren sorts children by priority and type
func (n *node) sortChildren() {
	sort.SliceStable(n.children, func(i, j int) bool {
		// Static nodes have highest priority
		if n.children[i].nodeType != n.children[j].nodeType {
			return n.children[i].nodeType < n.children[j].nodeType
		}
		// Then sort by priority (frequency of use)
		if n.children[i].priority != n.children[j].priority {
			return n.children[i].priority > n.children[j].priority
		}
		// Finally sort by path length (shorter paths first)
		return len(n.children[i].path) < len(n.children[j].path)
	})
}

// compressChain compresses single-child chains
func (n *node) compressChain() *node {
	if len(n.children) != 1 || n.isParam || n.isCatchAll {
		return n
	}

	child := n.children[0]
	if len(child.handlers) > 0 || child.isParam || child.isCatchAll {
		return n
	}

	// Merge with child
	n.path = n.path + child.path
	n.children = child.children
	for _, grandChild := range n.children {
		grandChild.parent = n
	}

	return n
}

// removeEmptyNodes removes nodes without handlers and single child
func (n *node) removeEmptyNodes() *node {
	if len(n.handlers) == 0 && len(n.children) == 1 && !n.isParam && !n.isCatchAll {
		child := n.children[0]
		child.path = n.path + child.path
		child.parent = n.parent
		return child
	}
	return n
}

// Helper functions
func longestCommonPrefix(nodes []*node) string {
	if len(nodes) == 0 {
		return ""
	}

	prefix := nodes[0].path
	for _, node := range nodes[1:] {
		for i := 0; i < len(prefix) && i < len(node.path); i++ {
			if prefix[i] != node.path[i] {
				prefix = prefix[:i]
				break
			}
		}
		if len(node.path) < len(prefix) {
			prefix = prefix[:len(node.path)]
		}
	}
	return prefix
}

// findRoute locates the appropriate route in the tree
func (n *node) findRoute(path string, params *Params) *node {
	// Handle root path
	if path == "/" && n.handler != nil {
		return n
	}

	// Split path into segments
	segments := strings.Split(strings.Trim(path, "/"), "/")
	currentNode := n

	for i := 0; i < len(segments); i++ {
		segment := segments[i]
		if segment == "" {
			continue
		}

		// Try to find static child first
		child := currentNode.getStaticChild(segment)

		// If no static child found, try parameter nodes
		if child == nil {
			child = currentNode.getParamChild()
			if child != nil {
				// Extract parameter value
				if params != nil {
					params.Add(child.paramName, segment)
				}
			}
		}

		// If still no child found, try catch-all
		if child == nil {
			child = currentNode.getCatchAllChild()
			if child != nil {
				// Extract remaining path as catch-all value
				if params != nil {
					remainingPath := strings.Join(segments[i:], "/")
					params.Add(child.paramName, remainingPath)
				}
				return child
			}
			return nil
		}

		currentNode = child
	}

	// Check if we found a handler
	if currentNode.handler != nil {
		return currentNode
	}

	return nil
}

// getStaticChild returns static child node matching the segment
func (n *node) getStaticChild(segment string) *node {
	for _, child := range n.children {
		if child.nodeType == staticNode && child.segment == segment {
			return child
		}
	}
	return nil
}

// getParamChild returns parameter child node if exists
func (n *node) getParamChild() *node {
	for _, child := range n.children {
		if child.nodeType == paramNode {
			return child
		}
	}
	return nil
}

// getCatchAllChild returns catch-all child node if exists
func (n *node) getCatchAllChild() *node {
	for _, child := range n.children {
		if child.nodeType == catchAllNode {
			return child
		}
	}
	return nil
}

// analyze collects statistics about the routing tree
func (n *node) analyze(stats *RouteStats, depth int) {
	if n == nil {
		return
	}

	// Update total nodes count
	stats.TotalNodes++

	// Update node type counts
	switch n.nodeType {
	case staticNode:
		stats.StaticNodes++
	case paramNode:
		stats.ParamNodes++
	case catchAllNode:
		stats.CatchAllNodes++
	}

	// Update depth statistics
	if depth > stats.MaxDepth {
		stats.MaxDepth = depth
	}

	// Calculate average depth (will be divided by TotalNodes later)
	stats.AverageDepth += float64(depth)

	// Count common prefixes
	if len(n.children) > 1 {
		prefix := longestCommonPrefix(n.children)
		if len(prefix) > 0 {
			stats.CommonPrefixes++
		}
	}

	// Additional statistics
	stats.ChildNodes += len(n.children)
	if len(n.handlers) > 0 {
		stats.HandlerNodes++
	}

	// Calculate branching factor
	if len(n.children) > stats.MaxBranchingFactor {
		stats.MaxBranchingFactor = len(n.children)
	}
	stats.TotalBranches += len(n.children)

	// Calculate path depth distribution
	pathDepth := len(strings.Split(n.fullPath, "/"))
	stats.PathDepthDistribution[pathDepth]++

	// Recursively analyze children
	for _, child := range n.children {
		child.analyze(stats, depth+1)
	}
}
