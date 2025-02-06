package airouterv3

import (
	"net/http"
	"strings"
)

type (
	// Handler is a custom handler function type
	Handler func(*Context)
)

func defaultNotFound(c *Context) {
	http.Error(c.ResponseWriter, "404 page not found", http.StatusNotFound)
}

// param struct - compact parameter storage
type param struct {
	key   string
	value string
}

// splitPath - optimized path splitting
func splitPath(path string) []string {
	if path == "/" {
		return nil
	}
	if path[0] == '/' {
		path = path[1:]
	}
	if path[len(path)-1] == '/' {
		path = path[:len(path)-1]
	}
	return strings.Split(path, "/")
}
