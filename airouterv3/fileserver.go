package airouterv3

import (
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type (
	// FileServer configuration
	FileServerConfig struct {
		Root            string            // Root directory for static files
		Index           string            // Index file (e.g., "index.html")
		MaxAge          time.Duration     // Cache control max age
		Compress        bool              // Enable compression
		CompressMinSize int64             // Minimum size for compression
		EtagEnabled     bool              // Enable ETag support
		DirList         bool              // Enable directory listing
		CustomHeaders   map[string]string // Custom headers for static files
		AllowedExt      []string          // Allowed file extensions
		Cache           FileCache         // File cache implementation
		ErrorHandler    ErrorHandler      // Custom error handler
		prefix          string
	}

	// FileCache interface for caching static files
	FileCache interface {
		Get(path string) (*CachedFile, bool)
		Set(path string, file *CachedFile)
		Remove(path string)
		Clear()
	}

	// CachedFile represents a cached static file
	CachedFile struct {
		Data       []byte
		ETag       string
		ModTime    time.Time
		Size       int64
		MimeType   string
		Compressed []byte
	}

	// FileServer handles static file serving
	FileServer struct {
		config FileServerConfig
		cache  FileCache
		pool   *sync.Pool // Compression buffer pool
	}

	// MemoryFileCache implements in-memory file caching
	MemoryFileCache struct {
		files map[string]*CachedFile
		mu    sync.RWMutex
	}
)

// Default configuration
var DefaultFileServerConfig = FileServerConfig{
	Index:           "index.html",
	MaxAge:          24 * time.Hour,
	Compress:        true,
	CompressMinSize: 1024, // 1KB
	EtagEnabled:     true,
	DirList:         false,
	CustomHeaders: map[string]string{
		"X-Content-Type-Options": "nosniff",
	},
	AllowedExt: []string{
		".css", ".js", ".html", ".htm", ".png", ".jpg", ".jpeg",
		".gif", ".svg", ".woff", ".woff2", ".ttf", ".eot",
	},
}

// Create new file server
func NewFileServer(config FileServerConfig) *FileServer {
	if config.Cache == nil {
		config.Cache = NewMemoryFileCache()
	}

	fs := &FileServer{
		config: config,
		cache:  config.Cache,
		pool: &sync.Pool{
			New: func() interface{} {
				return make([]byte, 32*1024) // 32KB buffer
			},
		},
	}

	return fs
}

// ServeHTTP implements http.Handler
func (fs *FileServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Println("File Server HIT")
	// Clean and validate path
	urlPath := path.Clean(r.URL.Path)
	if !fs.validatePath(urlPath) {
		w.WriteHeader(http.StatusForbidden)
		// fs.handleError(w, r, http.StatusForbidden, "Forbidden")
		return
	}
	fmt.Println("URLS PATH", urlPath)
	// Check cache
	if cached, ok := fs.cache.Get(urlPath); ok {
		fs.serveFromCache(w, r, cached)
		return
	}

	urlPath = strings.TrimPrefix(urlPath, fs.config.prefix)
	// Get file info
	filePath := filepath.Join(fs.config.Root, urlPath)

	if filePath[0] != '/' {
		filePath = "./" + filePath
	}

	info, err := os.Stat(filePath)
	fmt.Println("File Path", filePath, "Info", info, "Error", err)
	if err != nil {
		fmt.Println("Stat Error", err)
		if os.IsNotExist(err) {
			w.WriteHeader(http.StatusNotFound)
			// fs.handleError(w, r, http.StatusNotFound, "Not Found")
		} else {
			fmt.Println("Stat else Error", err)
			w.WriteHeader(http.StatusInternalServerError)
			// fs.handleError(w, r, http.StatusInternalServerError, "Internal Server Error")
		}
		return
	}

	// Handle directory
	if info.IsDir() {
		fs.handleDirectory(w, r, filePath, urlPath)
		return
	}

	// Serve file
	fs.serveFile(w, r, filePath, info)
}

// Cache implementation
func NewMemoryFileCache() *MemoryFileCache {
	return &MemoryFileCache{
		files: make(map[string]*CachedFile),
	}
}

func (c *MemoryFileCache) Get(path string) (*CachedFile, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	file, ok := c.files[path]
	return file, ok
}

func (c *MemoryFileCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.files = make(map[string]*CachedFile)
}

func (c *MemoryFileCache) Remove(path string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.files, path)
}

func (c *MemoryFileCache) Set(path string, file *CachedFile) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.files[path] = file
}

// Helper methods
func (fs *FileServer) validatePath(urlPath string) bool {
	if strings.Contains(urlPath, "..") {
		return false
	}

	if !fs.config.DirList && strings.HasSuffix(urlPath, "/") {
		return false
	}

	ext := filepath.Ext(urlPath)
	if ext != "" {
		allowed := false
		for _, allowedExt := range fs.config.AllowedExt {
			if ext == allowedExt {
				allowed = true
				break
			}
		}
		if !allowed {
			return false
		}
	}

	return true
}

func (fs *FileServer) serveFromCache(w http.ResponseWriter, r *http.Request, cached *CachedFile) {
	// Check if-none-match
	if fs.config.EtagEnabled {
		if etag := r.Header.Get("If-None-Match"); etag == cached.ETag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", cached.ETag)
	}

	// Set headers
	w.Header().Set("Content-Type", cached.MimeType)
	w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", int(fs.config.MaxAge.Seconds())))

	for k, v := range fs.config.CustomHeaders {
		w.Header().Set(k, v)
	}

	// Check if we can serve compressed version
	if fs.config.Compress && cached.Compressed != nil &&
		strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		w.Header().Set("Content-Encoding", "gzip")
		w.Write(cached.Compressed)
		return
	}

	w.Write(cached.Data)
}

func (fs *FileServer) serveFile(w http.ResponseWriter, r *http.Request, filePath string, info os.FileInfo) {
	// Read file
	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Println("ReadFile Error", err)
		w.WriteHeader(http.StatusInternalServerError)
		// fs.handleError(w, r, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	// Create cached file
	cached := &CachedFile{
		Data:     data,
		ModTime:  info.ModTime(),
		Size:     info.Size(),
		MimeType: mime.TypeByExtension(filepath.Ext(filePath)),
	}

	// Generate ETag
	if fs.config.EtagEnabled {
		hash := sha256.Sum256(data)
		cached.ETag = fmt.Sprintf(`"%x"`, hash[:16])
	}

	// Compress if needed
	if fs.config.Compress && info.Size() >= fs.config.CompressMinSize {
		cached.Compressed = fs.compress(data)
	}

	// Cache file
	fs.cache.Set(r.URL.Path, cached)

	// Serve file
	fs.serveFromCache(w, r, cached)
}

func (fs *FileServer) compress(data []byte) []byte {
	buf := new(strings.Builder)
	gz := gzip.NewWriter(buf)
	if _, err := gz.Write(data); err != nil {
		return nil
	}
	if err := gz.Close(); err != nil {
		return nil
	}
	return []byte(buf.String())
}

func (fs *FileServer) handleDirectory(w http.ResponseWriter, r *http.Request, dirPath, urlPath string) {
	// Check for index file
	if fs.config.Index != "" {
		indexPath := filepath.Join(dirPath, fs.config.Index)
		if info, err := os.Stat(indexPath); err == nil && !info.IsDir() {
			fs.serveFile(w, r, indexPath, info)
			return
		}
	}

	// Directory listing
	if !fs.config.DirList {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, "Directory listing not allowed")
		// fs.handleError(w, r, http.StatusForbidden, "Directory listing not allowed")
		return
	}

	entries, err := os.ReadDir(dirPath)
	if err != nil {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, "Error reading directory: %v", err)
		// fs.handleError(w, r, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<pre>\n")
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() {
			name += "/"
		}
		fmt.Fprintf(w, "<a href=\"%s\">%s</a>\n", path.Join(urlPath, name), name)
	}
	fmt.Fprintf(w, "</pre>\n")
}

// Router integration
func (r *Router) Static(prefix, root string, config ...FileServerConfig) {
	cfg := DefaultFileServerConfig
	if len(config) > 0 {
		cfg = config[0]
	}
	cfg.Root = root
	cfg.prefix = prefix

	fs := NewFileServer(cfg)
	r.Get(prefix+"/*path", func(c *Context) {
		fs.ServeHTTP(c.ResponseWriter, c.Request)
	})
}

// // Usage example
// func main() {
// 	router := NewRouter()

// 	// Basic static file serving
// 	router.Static("/static", "./public")

// 	// Custom configuration
// 	router.Static("/assets", "./assets", FileServerConfig{
// 		MaxAge:     12 * time.Hour,
// 		Compress:   true,
// 		DirList:    true,
// 		AllowedExt: []string{".pdf", ".doc", ".docx"},
// 		CustomHeaders: map[string]string{
// 			"Access-Control-Allow-Origin": "*",
// 		},
// 	})

// 	// Single file handler
// 	router.StaticFile("/favicon.ico", "./public/favicon.ico")

// 	// Custom file system
// 	router.StaticFS("/custom", http.Dir("./custom"))
// }

// Additional helper methods
func (r *Router) StaticFile(path, filepath string) {
	r.Get(path, func(c *Context) {
		http.ServeFile(c.ResponseWriter, c.Request, filepath)
	})
}

func (r *Router) StaticFS(prefix string, fs http.FileSystem) {
	handler := http.StripPrefix(prefix, http.FileServer(fs))
	r.Get(prefix+"/*path", func(c *Context) {
		handler.ServeHTTP(c.ResponseWriter, c.Request)
	})
}

// Cache management
type CacheStats struct {
	Hits      int64
	Misses    int64
	Size      int64
	Items     int
	Evictions int64
}

type CacheManager struct {
	cache  FileCache
	stats  CacheStats
	maxAge time.Duration
	mu     sync.RWMutex
}

func (cm *CacheManager) Start() {
	go cm.cleanupLoop()
}

func (cm *CacheManager) cleanupLoop() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		cm.cleanup()
	}
}

func (cm *CacheManager) cleanup() {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Implement cache cleanup logic
}
