package airouterv3

// middlewareEntry represents a middleware with its must-run flag
type middlewareEntry struct {
	handler Middleware
	must    bool
}

// Add these types
type (
	// Middleware function type
	Middleware func(*Context) bool
	AbortType  int
)

// Add these constants
const (
	Continue AbortType = iota
	Abort
)

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
