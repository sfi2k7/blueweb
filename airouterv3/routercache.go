package airouterv3

import "sync"

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
