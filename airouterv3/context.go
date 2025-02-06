package airouterv3

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
)

var templateCache = &TemplateCache{templates: make(map[string]*template.Template)}

// Context holds the request context
type Context struct {
	Request        *http.Request
	ResponseWriter http.ResponseWriter
	query          url.Values
	headers        map[string][]string
	queryParsed    bool
	headersParsed  bool
	bodyParsed     bool
	start          time.Time
	store          map[string]interface{}

	params        [8]param // fixed size array for common cases
	pCount        int      // param count
	signaltype    AbortType
	multipartForm *multipart.Form
	maxMemory     int64
	formData      url.Values
	path          string
}

func (c *Context) Abort() {
	c.signaltype = Abort
}

func (c *Context) Reset(w http.ResponseWriter, r *http.Request) {
	c.start = time.Now()
	c.Request = r
	c.ResponseWriter = w

	c.queryParsed = false
	c.headersParsed = false
	c.signaltype = Continue
	c.pCount = 0
	// c.params = [8]param{}
}

// GetQuery returns query parameter value (lazy parsing)
func (c *Context) Query(name string) string {
	if !c.queryParsed {
		c.query = c.Request.URL.Query()
		c.queryParsed = true
	}
	if values, ok := c.query[name]; ok && len(values) > 0 {
		return values[0]
	}
	return ""
}

// GetHeader returns header value (lazy parsing)
func (c *Context) GetHeader(name string) string {
	if !c.headersParsed {
		c.headers = c.Request.Header
		c.headersParsed = true
	}
	if values, ok := c.headers[name]; ok && len(values) > 0 {
		return values[0]
	}
	return ""
}

// GetBody returns the request body
func (c *Context) GetBody() []byte {
	body := make([]byte, c.Request.ContentLength)
	c.Request.Body.Read(body)
	return body
}

func (c *Context) WriteHeader(status int) {
	c.ResponseWriter.WriteHeader(status)
}

func (c *Context) Write(data []byte) (int, error) {
	return c.ResponseWriter.Write(data)
}

func (c *Context) Redirect(url string, status int) {
	c.ResponseWriter.Header().Set("Location", url)
	c.ResponseWriter.WriteHeader(status)
}

func (c *Context) SetHeader(key, value string) {
	c.ResponseWriter.Header().Set(key, value)
}

func (c *Context) SetContentType(contentType string) {
	c.ResponseWriter.Header().Set("Content-Type", contentType)
}

func (c *Context) String(data string) {
	c.ResponseWriter.Write([]byte(data))
}

func (c *Context) HTML(data string) {
	c.SetContentType("text/html")
	c.ResponseWriter.Write([]byte(data))
}

func (c *Context) Text(data string) {
	c.SetContentType("text/plain")
	c.ResponseWriter.Write([]byte(data))
}

func (c *Context) View(filepath string, data interface{}, useTemplateCache ...bool) error {
	if len(useTemplateCache) > 0 && useTemplateCache[0] {
		return c.ViewWithCache(filepath, data, templateCache)
	}

	// Create a template cache if you're using this frequently
	const defaultContentType = "text/html; charset=utf-8"

	// Read template file
	tmpl, err := c.parseTemplate(filepath)
	if err != nil {
		return c.handleError(err, http.StatusNotFound)
	}

	// Set proper content type header
	c.SetHeader("Content-Type", defaultContentType)

	// Execute template
	if err := c.executeTemplate(tmpl, data); err != nil {
		fmt.Println("Error executing template", err)
		return c.handleError(err, http.StatusInternalServerError)
	}

	// c.Status(http.StatusOK)
	return nil
}

// Helper methods
func (c *Context) parseTemplate(filepath string) (*template.Template, error) {
	bts, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read template file: %w", err)
	}

	tmpl, err := template.New(filepath).Parse(string(bts))
	if err != nil {
		return nil, fmt.Errorf("failed to parse template: %w", err)
	}

	return tmpl, nil
}

func (c *Context) executeTemplate(tmpl *template.Template, data interface{}) error {
	if err := tmpl.Execute(c.ResponseWriter, data); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}
	return nil
}

func (c *Context) handleError(err error, status int) error {
	fmt.Println("Error bein ghandled?")
	c.Status(status)
	return fmt.Errorf("view error: %w", err)
}

func (c *Context) Status(status int) {
	fmt.Println("Sending status", status)
	c.ResponseWriter.WriteHeader(status)
}

func (c *Context) Took() int64 {
	return time.Since(c.start).Microseconds()
}

// BuildURL helper method for Context
func (c *Context) BuildURL(name string, params map[string]string) (string, error) {
	// Access router through request context or store it in Context during initialization
	if router, ok := c.store["router"].(*Router); ok {
		return router.URL(name, params)
	}
	return "", fmt.Errorf("router not found in context")
}

func (c *Context) Json(data interface{}) error {

	jsoned, err := json.Marshal(data)
	if err != nil {
		return err
	}
	c.ResponseWriter.Header().Set("Content-Type", "application/json")
	c.ResponseWriter.Write(jsoned)
	return nil
}

// func (c *Context) ParseJson(data interface{}) error {
// 	decoder := json.NewDecoder(c.Request.Body)
// 	return decoder.Decode(data)
// }

func (c *Context) GetValue(key string) interface{} {
	return c.store[key]
}

func (c *Context) SetValue(key string, value interface{}) {
	c.store[key] = value
}

// Param - optimized parameter lookup
func (c *Context) Param(name string) string {
	for i := 0; i < c.pCount; i++ {
		if c.params[i].key == name {
			return c.params[i].value
		}
	}
	return ""
}

// Body parsing methods for Context
func (c *Context) ParseJson(v interface{}) error {
	if !c.bodyParsed {
		if c.Request.Body == nil {
			return fmt.Errorf("empty body")
		}

		router, ok := c.store["router"].(*Router)
		if !ok {
			return fmt.Errorf("router not found in context")
		}

		// Use body pool
		buf := router.bodyPool.Get().([]byte)
		defer router.bodyPool.Put(buf)

		// Limit body size
		r := io.LimitReader(c.Request.Body, router.maxBodySize)
		if _, err := r.Read(buf); err != nil && err != io.EOF {
			return err
		}

		if err := json.Unmarshal(buf, v); err != nil {
			return err
		}
		c.bodyParsed = true
	}
	return nil
}

func (c *Context) parseForm() {
	if c.Request.Form == nil {
		c.Request.ParseForm()
	}
	c.formData = c.Request.Form
}

// Form parsing methods
func (c *Context) FormValue(key string) string {
	if !c.bodyParsed {
		c.Request.ParseForm()

		c.parseForm()
	}
	return c.formData.Get(key)
}

func (c *Context) FormInt(key string) (int, error) {
	return strconv.Atoi(c.FormValue(key))
}

func (c *Context) FormInt64(key string) (int64, error) {
	return strconv.ParseInt(c.FormValue(key), 10, 64)
}

func (c *Context) FormFloat64(key string) (float64, error) {
	return strconv.ParseFloat(c.FormValue(key), 64)
}

func (c *Context) FormBool(key string) (bool, error) {
	return strconv.ParseBool(c.FormValue(key))
}

func (c *Context) FormTime(key, layout string) (time.Time, error) {
	return time.Parse(layout, c.FormValue(key))
}

// Query string parsing methods
func (c *Context) QueryInt(key string, defaultVal int) int {
	if val, err := strconv.Atoi(c.Query(key)); err == nil {
		return val
	}
	return defaultVal
}

func (c *Context) QueryInt64(key string, defaultVal int64) int64 {
	if val, err := strconv.ParseInt(c.Query(key), 10, 64); err == nil {
		return val
	}
	return defaultVal
}

func (c *Context) QueryFloat64(key string, defaultVal float64) float64 {
	if val, err := strconv.ParseFloat(c.Query(key), 64); err == nil {
		return val
	}
	return defaultVal
}

func (c *Context) QueryBool(key string, defaultVal bool) bool {
	if val, err := strconv.ParseBool(c.Query(key)); err == nil {
		return val
	}
	return defaultVal
}

func (c *Context) QueryTime(key, layout string, defaultVal time.Time) time.Time {
	if val, err := time.Parse(layout, c.Query(key)); err == nil {
		return val
	}
	return defaultVal
}

func (c *Context) QueryDuration(key string, defaultVal time.Duration) time.Duration {
	if val, err := time.ParseDuration(c.Query(key)); err == nil {
		return val
	}
	return defaultVal
}

// File handling methods
func (c *Context) FormFile(key string) (*multipart.FileHeader, error) {
	if c.multipartForm == nil {
		if err := c.Request.ParseMultipartForm(c.maxMemory); err != nil {
			return nil, err
		}
		c.multipartForm = c.Request.MultipartForm
	}
	file, header, err := c.Request.FormFile(key)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return header, nil
}

// Security helpers
func (c *Context) SetSecureHeaders() {
	h := c.ResponseWriter.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-XSS-Protection", "1; mode=block")
	h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	h.Set("Content-Security-Policy", "default-src 'self'")
}

// JoinPath joins path segments and normalizes the result
func (c *Context) JoinPath(segments ...string) string {
	joined := path.Join(segments...)
	if !strings.HasPrefix(joined, "/") {
		joined = "/" + joined
	}
	return joined
}

// IsValidPath checks if the given path is valid
func (c *Context) IsValidPath(path string) bool {
	return isValidPath(path)
}
