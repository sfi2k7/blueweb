package airouterv3

import (
	"html/template"
	"net/http"
	"sync"
)

// You could add template caching to improve performance
type TemplateCache struct {
	sync.RWMutex
	templates map[string]*template.Template
}

func (c *Context) ViewWithCache(filepath string, data interface{}, cache *TemplateCache) error {
	cache.RLock()
	tmpl, exists := cache.templates[filepath]
	cache.RUnlock()

	if !exists {
		cache.Lock()
		defer cache.Unlock()

		// Double-check after acquiring lock
		if tmpl, exists = cache.templates[filepath]; !exists {
			var err error
			tmpl, err = c.parseTemplate(filepath)
			if err != nil {
				return c.handleError(err, http.StatusNotFound)
			}
			cache.templates[filepath] = tmpl
		}
	}

	// Rest of the code...
	return c.executeTemplate(tmpl, data)
}
