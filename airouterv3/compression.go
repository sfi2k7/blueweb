package airouterv3

import (
	"bufio"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
)

type (
	// CompressionConfig holds configuration for compression middleware
	CompressionConfig struct {
		// Compression level (-2 to 11 for Brotli, -1 to 9 for Gzip/Deflate)
		Level int

		// Minimum size in bytes before compressing
		MinSize int64

		// Content types to compress
		Types []string

		// Content types to exclude
		ExcludeTypes []string

		// Paths to exclude
		ExcludePaths []string

		// Enable dynamic compression level based on CPU usage
		DynamicLevel bool

		// Pool size for compression writers
		PoolSize int

		// Whether to prefer Brotli over Gzip when available
		PreferBrotli bool
	}

	// Compression writer interface
	compressionWriter interface {
		io.WriteCloser
		Reset(io.Writer)
		Flush() error
	}

	// Compression response writer
	compressResponseWriter struct {
		http.ResponseWriter
		compressor compressionWriter
		config     *CompressionConfig
		written    int64
		statusCode int
		headerSent bool
		pool       *compressionPool
	}

	// Compression pools
	compressionPool struct {
		gzipPool sync.Pool
		// brotliPool  sync.Pool
		deflatePool sync.Pool
		bufferPool  sync.Pool
	}
)

// Default compression config
var DefaultCompressionConfig = CompressionConfig{
	Level:   6,
	MinSize: 1024, // 1KB
	Types: []string{
		"text/html",
		"text/css",
		"text/plain",
		"text/javascript",
		"application/javascript",
		"application/x-javascript",
		"application/json",
		"application/xml",
		"application/x-yaml",
		"application/yaml",
		"image/svg+xml",
		"application/wasm",
	},
	ExcludeTypes: []string{
		"image/jpeg",
		"image/png",
		"image/gif",
		"image/webp",
		"audio/",
		"video/",
	},
	ExcludePaths: []string{
		"/assets/images/",
		"/downloads/",
	},
	DynamicLevel: true,
	PoolSize:     1000,
	// PreferBrotli: true,
}

// Compression middleware
func Compression(config ...CompressionConfig) Middleware {
	// Use default config if none provided
	cfg := DefaultCompressionConfig
	if len(config) > 0 {
		cfg = config[0]
	}

	// Initialize compression pools
	pool := &compressionPool{
		gzipPool: sync.Pool{
			New: func() interface{} {
				gz, _ := gzip.NewWriterLevel(nil, cfg.Level)
				return gz
			},
		},
		// brotliPool: sync.Pool{
		// 	New: func() interface{} {
		// 		br, _ := brotli.NewWriterLevel(nil, cfg.Level)
		// 		return br
		// 	},
		// },
		deflatePool: sync.Pool{
			New: func() interface{} {
				df, _ := zlib.NewWriterLevel(nil, cfg.Level)
				return df
			},
		},
		bufferPool: sync.Pool{
			New: func() interface{} {
				return bufio.NewWriterSize(nil, 4096)
			},
		},
	}

	return func(c *Context) bool {
		// Check if compression should be skipped
		if shouldSkipCompression(c, &cfg) {
			return true
		}

		// Get the appropriate compressor
		encoding, compressor := getCompressor(c.Request, &cfg, pool)
		if compressor == nil {
			return true
		}

		// Create compressed response writer
		cw := &compressResponseWriter{
			ResponseWriter: c.ResponseWriter,
			compressor:     compressor,
			config:         &cfg,
			pool:           pool,
		}

		// Set compression headers
		c.ResponseWriter.Header().Set("Content-Encoding", encoding)
		c.ResponseWriter.Header().Set("Vary", "Accept-Encoding")

		// Replace response writer
		c.ResponseWriter = cw
		defer cw.Close()

		return true
	}
}

// Helper functions
func shouldSkipCompression(c *Context, cfg *CompressionConfig) bool {
	// Check if already compressed
	if c.ResponseWriter.Header().Get("Content-Encoding") != "" {
		return true
	}

	// Check excluded paths
	for _, path := range cfg.ExcludePaths {
		if strings.HasPrefix(c.Request.URL.Path, path) {
			return true
		}
	}

	// Check content type
	contentType := c.ResponseWriter.Header().Get("Content-Type")
	if contentType != "" {
		// Check excluded types
		for _, excluded := range cfg.ExcludeTypes {
			if strings.HasPrefix(contentType, excluded) {
				return true
			}
		}

		// Check included types
		isIncluded := false
		for _, included := range cfg.Types {
			if strings.HasPrefix(contentType, included) {
				isIncluded = true
				break
			}
		}
		if !isIncluded {
			return true
		}
	}

	return false
}

func getCompressor(r *http.Request, cfg *CompressionConfig, pool *compressionPool) (string, compressionWriter) {
	acceptEncoding := r.Header.Get("Accept-Encoding")

	// Check for Brotli support
	// if cfg.PreferBrotli && strings.Contains(acceptEncoding, "br") {
	// 	return "br", pool.getBrotliWriter()
	// }

	// Check for Gzip support
	if strings.Contains(acceptEncoding, "gzip") {
		return "gzip", pool.getGzipWriter()
	}

	// Check for Deflate support
	if strings.Contains(acceptEncoding, "deflate") {
		return "deflate", pool.getDeflateWriter()
	}

	return "", nil
}

// Compression response writer methods
func (cw *compressResponseWriter) Write(b []byte) (int, error) {
	if !cw.headerSent {
		if cw.statusCode == 0 {
			cw.statusCode = http.StatusOK
		}
		cw.ResponseWriter.WriteHeader(cw.statusCode)
		cw.headerSent = true
	}

	size := len(b)
	cw.written += int64(size)

	// Skip compression for small responses
	if cw.written < cw.config.MinSize {
		return cw.ResponseWriter.Write(b)
	}

	return cw.compressor.Write(b)
}

func (cw *compressResponseWriter) WriteHeader(statusCode int) {
	if cw.headerSent {
		return
	}

	cw.statusCode = statusCode
	if shouldSkipCompressionForStatus(statusCode) {
		cw.ResponseWriter.WriteHeader(statusCode)
		cw.headerSent = true
	}
}

func (cw *compressResponseWriter) Close() error {
	fmt.Println("Closing Compressor")
	if cw.compressor != nil {
		err := cw.compressor.Close()
		switch v := cw.compressor.(type) {
		case *gzip.Writer:
			cw.pool.gzipPool.Put(v)
		// case *brotli.Writer:
		// 	cw.pool.brotliPool.Put(v)
		case *zlib.Writer:
			cw.pool.deflatePool.Put(v)
		}
		return err
	}
	return nil
}

func (cw *compressResponseWriter) Flush() {
	if f, ok := cw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
	if cw.compressor != nil {
		cw.compressor.Flush()
	}
}

// Implement CloseNotifier, Hijacker, etc.
func (cw *compressResponseWriter) CloseNotify() <-chan bool {
	if cn, ok := cw.ResponseWriter.(http.CloseNotifier); ok {
		return cn.CloseNotify()
	}
	return nil
}

func (cw *compressResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := cw.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

// Pool methods
func (p *compressionPool) getGzipWriter() *gzip.Writer {
	w := p.gzipPool.Get().(*gzip.Writer)
	w.Reset(nil)
	return w
}

// func (p *compressionPool) getBrotliWriter() *brotli.Writer {
// 	w := p.brotliPool.Get().(*brotli.Writer)
// 	w.Reset(nil)
// 	return w
// }

func (p *compressionPool) getDeflateWriter() *zlib.Writer {
	w := p.deflatePool.Get().(*zlib.Writer)
	w.Reset(nil)
	return w
}

// Helper functions
func shouldSkipCompressionForStatus(status int) bool {
	return status < 200 || status == 204 || status == 304
}

// Dynamic compression level based on CPU usage
func getDynamicCompressionLevel(cfg *CompressionConfig) int {
	if !cfg.DynamicLevel {
		return cfg.Level
	}

	// Implement CPU usage check and adjust level accordingly
	// For example:
	// cpuUsage := getCPUUsage()
	// if cpuUsage > 80 {
	//     return 1 // Fastest compression
	// } else if cpuUsage > 60 {
	//     return 4 // Balanced
	// }
	// return cfg.Level
	return cfg.Level
}
