package airouter4

package main

import (
	"net/http"
	"strings"
)

type NodeType int

const (
	Static NodeType = iota
	Param
	CatchAll
)

// HandlerFunc defines the request handler used by the router.
type HandlerFunc func(http.ResponseWriter, *http.Request, Params)

// Params stores URL parameters and their values.
type Params map[string]string

// Node represents a single node in the trie.
type Node struct {
	children map[string]*Node
	handler  HandlerFunc
	param    string
	nodeType NodeType
}

// Match searches for a handler for a given request path.
func (n *Node) Match(segs []string, params Params) (HandlerFunc, Params) {
	if len(segs) == 0 {
		return n.handler, params
	}

	seg := segs[0]

	// Match static routes
	if child, found := n.children[seg]; found && child.nodeType == Static {
		if handler, params := child.Match(segs[1:], params); handler != nil {
			return handler, params
		}
	}

	// Match parametric routes
	for _, child := range n.children {
		if child.nodeType == Param {
			params[child.param] = seg
			if handler, params := child.Match(segs[1:], params); handler != nil {
				return handler, params
			}
		}
	}

	// Match catch-all routes
	for _, child := range n.children {
		if child.nodeType == CatchAll {
			params[child.param] = strings.Join(segs, "/")
			return child.handler, params
		}
	}

	return nil, nil
}

// Router is a trie-based router.
type Router struct {
	roots map[string]*Node // The roots for each HTTP method.
}

// NewRouter creates a new Router instance.
func NewRouter() *Router {
	return &Router{
		roots: make(map[string]*Node),
	}
}

// AddRoute adds a new route with a specified method to the router.
func (r *Router) AddRoute(method, path string, handler HandlerFunc) {
	if _, exists := r.roots[method]; !exists {
		r.roots[method] = &Node{children: make(map[string]*Node)}
	}
	segs := strings.Split(path, "/")[1:]
	r.roots[method].addRoute(segs, handler)
}

// Define HTTP methods.
func (r *Router) Get(path string, handler HandlerFunc) {
	r.AddRoute(http.MethodGet, path, handler)
}

func (r *Router) Post(path string, handler HandlerFunc) {
	r.AddRoute(http.MethodPost, path, handler)
}

// ServeHTTP makes the router satisfy the http.Handler interface.
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	root := r.roots[req.Method]
	if root == nil {
		http.NotFound(w, req)
		return
	}

	segs := strings.Split(strings.Trim(req.URL.Path, "/"), "/")
	if handler, params := root.Match(segs, Params{}); handler != nil {
		handler(w, req, params)
	} else {
		http.NotFound(w, req)
	}
}

// AddRoute adds a new route underneath a node.
func (n *Node) addRoute(segs []string, handler HandlerFunc) {
	if len(segs) == 0 {
		n.handler = handler
		return
	}

	seg := segs[0]
	var child *Node

	switch {
	case seg == "*":
		child = &Node{children: make(map[string]*Node), nodeType: CatchAll, param: "path"}
	case strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}"):
		paramName := seg[1 : len(seg)-1]
		child = &Node{children: make(map[string]*Node), nodeType: Param, param: paramName}
	default:
		if n.children[seg] == nil {
			n.children[seg] = &Node{children: make(map[string]*Node), nodeType: Static}
		}
		child = n.children[seg]
	}

	n.children[seg] = child
	child.addRoute(segs[1:], handler)
}
