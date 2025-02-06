package airouterv3

import (
	"net/http"
	"strings"
)

// Route represents a route group
type Route struct {
	prefix         string
	router         *Router
	middleware     []middlewareEntry
	mustmiddleware []middlewareEntry
	name           string
}

func (r *Router) Group(prefix string) *Route {
	return &Route{
		prefix: prefix,
		router: r,
	}
}

// Name sets the name for a route group
func (g *Route) Name(name string) *Route {
	if g.router.lastPath != "" {
		fullName := g.name
		if fullName != "" && name != "" {
			fullName += "."
		}
		fullName += name

		g.router.namedRoutes[fullName] = RouteInfo{
			path:       g.router.lastPath,
			params:     extractParams(g.router.lastPath),
			isWildcard: strings.Contains(g.router.lastPath, "*"),
		}
	}
	return g
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
		g.mustmiddleware = append(g.mustmiddleware, middlewareEntry{handler: m, must: true})
	}
	return g
}

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

func (g *Route) Add(method, path string, handlers ...Handler) {
	fullPath := g.prefix + path

	// Create wrapper handler that executes middleware chain and handlers
	finalHandler := func(c *Context) {
		// Execute group middleware first
		shouldContinue := true
		for _, mw := range g.middleware {
			shouldContinue = mw.handler(c)
			if !shouldContinue {
				break
			}
		}

		// Execute all provided handlers in order
		if shouldContinue {
			for _, h := range handlers {
				h(c)
			}
		}

		// Execute group must middleware last
		for _, mw := range g.mustmiddleware {

			mw.handler(c)

			if c.signaltype == Abort {
				return
			}
		}
	}

	// Add the single combined handler to the router
	g.router.Add(method, fullPath, finalHandler)
}
