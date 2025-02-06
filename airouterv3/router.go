package airouterv3

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"runtime/debug"
	"strings"
	"sync"
)

type Router struct {
	tree           *node
	pool           sync.Pool
	bodyPool       sync.Pool
	NotFound       Handler
	middleware     []middlewareEntry
	mustMiddleware []middlewareEntry
	//Error handling
	errorHandlers    map[int]ErrorHandler // Status code specific handlers
	errorHandler     ErrorHandler         // Global error handler
	panicHandler     ErrorHandler         // Panic recovery handler
	notFoundHandler  Handler              // 404 handler
	methodNotAllowed Handler              // 405 handler
	//Named Routes
	namedRoutes      map[string]RouteInfo
	lastPath         string
	maxBodySize      int64
	cache            *RouterCache
	corsConfig       *CORSConfig
	automaticOPTIONS bool // flag to enable/disable automatic OPTIONS handling
	pathConfig       PathConfig
	regexCache       map[string]*regexp.Regexp
	websockets       map[string]*WebSocketManager
	hub              *Hub
}

// New creates a new router instance
func New() *Router {
	r := &Router{
		tree: &node{
			path:     "/",
			handler:  make(map[string]Handler),
			children: make([]*node, 0),
		},
		errorHandlers:    make(map[int]ErrorHandler),
		namedRoutes:      make(map[string]RouteInfo),
		cache:            &RouterCache{},
		maxBodySize:      10 << 20,          // 10 MB
		automaticOPTIONS: true,              // Enable by default
		corsConfig:       defaultCORSConfig, // Use default CORS config
	}

	r.bodyPool.New = func() interface{} {
		return make([]byte, 32*1024) // 32 KB
	}

	r.pool.New = func() interface{} {
		c := &Context{
			store: make(map[string]interface{}),
		}
		c.store["router"] = r
		return c
	}

	// r.NotFound = func(c *Context) {
	// 	c.ResponseWriter.WriteHeader(http.StatusNotFound)
	// }

	r.setDefaultErrorHandlers()

	return r
}

// Add these methods to the Router implementation

// ListenAndServe starts the server with optional SSL support
func (r *Router) ListenAndServe(addr string, sslConfig *SSLConfig) error {
	server := &http.Server{
		Addr:    addr,
		Handler: r,
	}

	if sslConfig != nil && sslConfig.Enabled {
		if sslConfig.AutoTLS {
			return r.serveAutoTLS(server, sslConfig)
		}
		return r.serveManualTLS(server, sslConfig)
	}

	return server.ListenAndServe()
}

func (r *Router) PrintRoutes() string {
	var sb strings.Builder
	r.printNode(&sb, r.tree, 0)
	return sb.String()
}

func (r *Router) printNode(sb *strings.Builder, n *node, level int) {
	indent := strings.Repeat("  ", level)
	sb.WriteString(fmt.Sprintf("%s%s\n", indent, n.path))
	for _, child := range n.children {
		r.printNode(sb, child, level+1)
	}
}

// convenience methods for HTTP methods
func (r *Router) Get(path string, handler Handler) {
	fmt.Println("Adding GET path:", path)
	r.Add(http.MethodGet, path, handler)
}
func (r *Router) Post(path string, handler Handler)   { r.Add(http.MethodPost, path, handler) }
func (r *Router) Put(path string, handler Handler)    { r.Add(http.MethodPut, path, handler) }
func (r *Router) Delete(path string, handler Handler) { r.Add(http.MethodDelete, path, handler) }

// // Use adds a new middleware to the chain
// func (r *Router) Use(middleware ...Middleware) {
// 	r.middleware = append(r.middleware, middleware...)
// }

// // UseMust adds a must-run middleware
// func (r *Router) UseMust(middleware ...Middleware) {
// 	r.mustMiddleware = append(r.mustMiddleware, middleware...)
// }

// ResetMiddleware clears all middleware
func (r *Router) ResetMiddleware() {
	r.middleware = nil
	// r.mustMiddleware = nil
}

// ServeHTTP - updated to handle catch-all routes
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if !isValidPath(req.URL.Path) {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	urlpath := req.URL.Path
	if normalized, shouldRedirect := r.normalizePath(urlpath); shouldRedirect {
		// Preserve query string in redirect
		if req.URL.RawQuery != "" {
			normalized += "?" + req.URL.RawQuery
		}
		http.Redirect(w, req, normalized, http.StatusMovedPermanently)
		return
	}

	ctx := r.pool.Get().(*Context)
	ctx.Reset(w, req)

	defer r.pool.Put(ctx)

	// Panic recovery
	defer func() {
		if err := recover(); err != nil {
			if r.panicHandler != nil {
				r.panicHandler(ctx, fmt.Errorf("panic: %v\n%s", err, debug.Stack()))
			} else {
				fmt.Println("Panic recovery Error (SERGE HTTP):", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}
	}()

	r.handleCORS(ctx)

	// Handle OPTIONS request
	if r.automaticOPTIONS && req.Method == http.MethodOptions {
		if r.corsConfig != nil {
			// CORS headers are already set by handleCORS
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}

	// Handle middleware
	for i := 0; i < len(r.middleware); i++ {
		if !r.middleware[i].handler(ctx) {
			return
		}
	}

	// Find route
	current := r.tree
	path := req.URL.Path
	if path == "/" {
		if h := current.handler[req.Method]; h != nil {
			h(ctx)
			return
		}

		if r.methodNotAllowed != nil {
			r.methodNotAllowed(ctx)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}

	segments := splitPath(path)
	for i, segment := range segments {
		found := false
		for _, child := range current.children {
			// Check for catch-all route
			if child.isCatchAll {
				if ctx.pCount < 8 {
					// Join remaining segments for catch-all value
					remainingPath := strings.Join(segments[i:], "/")
					ctx.params[ctx.pCount].key = child.param
					ctx.params[ctx.pCount].value = remainingPath
					ctx.pCount++
				}

				if h := child.handler[req.Method]; h != nil {
					h(ctx)
					return
				}
				r.NotFound(ctx)
				return
			}

			// Normal route matching
			if child.path == segment || child.param != "" {
				if child.param != "" && ctx.pCount < 8 {

					//
					// Check regex if present
					ismatch := true
					if child.paramDef.Regex != nil {
						ismatch = false
						if !child.paramDef.Regex.MatchString(segment) {
							ismatch = true
							if child.paramDef.IsOptional {
								ctx.params[ctx.pCount].key = child.paramDef.Name
								ctx.params[ctx.pCount].value = child.paramDef.Name
								ctx.pCount++
								break
							}
							continue
						}
					}

					if ismatch {
						fmt.Println("isMatch: Segment:", segment)
						fmt.Println("isMatch: Segment:", segment)
						fmt.Println("isMatch: Param:", child.param)
					}

					ctx.params[ctx.pCount].key = child.param
					ctx.params[ctx.pCount].value = segment
					ctx.pCount++
				}
				current = child
				found = true
				break
			}
		}

		if !found {
			r.handleError(ctx, errors.New("Route not found:"+path))
			return
		}

		if i == len(segments)-1 {
			if h := current.handler[req.Method]; h != nil {
				h(ctx)
			} else {
				defaultNotFound(ctx)
			}
		}
	}

	// Fast path for must middleware
	for i := 0; i < len(r.mustMiddleware); i++ {
		r.mustMiddleware[i].handler(ctx)
		if ctx.signaltype == Abort {
			return
		}
	}
}

// Add method - updated to handle catch-all routes
func (r *Router) Add(method, path string, handler Handler) {
	r.lastPath = path
	if path == "/" {
		r.tree.handler[method] = handler
		return
	}

	current := r.tree
	segments := splitPath(path)

	for i, segment := range segments {
		isParam := segment[0] == '{' && segment[len(segment)-1] == '}'

		var paramDef *ParamDefinition
		if isParam {
			var err error
			paramDef, err = parseParam(segment)
			if err != nil {
				panic(err)
				// return fmt.Errorf("invalid parameter pattern '%s': %v", segment, err)
			}
		}

		isCatchAll := segment == "*path" || segment == "*" // support both formats

		// If this is a catch-all route, it must be the last segment
		if isCatchAll && i != len(segments)-1 {
			panic("catch-all route must be the last segment")
		}

		child := current.findChild(segment)
		if child == nil {
			child = &node{
				path:     segment,
				handler:  make(map[string]Handler),
				isStatic: !isParam && !isCatchAll,
				paramDef: paramDef,
			}

			if isParam {
				child.param = segment[1 : len(segment)-1]
				if paramDef != nil {
					child.param = paramDef.Name
				}
				child.isParam = true
			}

			if isCatchAll {
				child.isCatchAll = true
				child.param = "path" // store the catch-all parameter name
			}
			current.children = append(current.children, child)
		}
		current = child
	}
	current.handler[method] = handler
}

func (c *Router) StartHub() {
	c.hub = NewHub()
	go c.hub.Run()
}
