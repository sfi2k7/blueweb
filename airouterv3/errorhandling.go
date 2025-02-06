package airouterv3

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// Add these new types and constants
type (
	// ErrorHandler is a function that handles errors
	ErrorHandler func(*Context, error)

	// HTTPError represents an HTTP error
	HTTPError struct {
		Code    int
		Message string
		Err     error // Original error
	}
)

// Error implements the error interface
func (e *HTTPError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("HTTP %d: %s: %v", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("HTTP %d: %s", e.Code, e.Message)
}

// SetErrorHandler sets the global error handler
func (r *Router) SetErrorHandler(handler ErrorHandler) {
	r.errorHandler = handler
}

// SetPanicHandler sets the panic recovery handler
func (r *Router) SetPanicHandler(handler ErrorHandler) {
	r.panicHandler = handler
}

// SetNotFoundHandler sets the 404 handler
func (r *Router) SetNotFoundHandler(handler Handler) {
	r.notFoundHandler = handler
}

// SetMethodNotAllowedHandler sets the 405 handler
func (r *Router) SetMethodNotAllowedHandler(handler Handler) {
	r.methodNotAllowed = handler
}

// OnError sets an error handler for a specific status code
func (r *Router) OnError(code int, handler ErrorHandler) {
	r.errorHandlers[code] = handler
}

// handleError processes an error through the appropriate handler
func (r *Router) handleError(ctx *Context, err error) {
	if err == nil {
		return
	}

	var httpError *HTTPError
	if e, ok := err.(*HTTPError); ok {
		httpError = e
	} else {
		fmt.Println(" Error in handle error:", err)
		// Convert regular error to HTTPError
		httpError = &HTTPError{
			Code:    http.StatusInternalServerError,
			Message: err.Error(),
			Err:     err,
		}
	}

	// Find appropriate handler
	if handler, ok := r.errorHandlers[httpError.Code]; ok {
		handler(ctx, httpError)
		return
	}

	// Fall back to global error handler
	if r.errorHandler != nil {
		r.errorHandler(ctx, httpError)
		return
	}

	// Default error response
	http.Error(ctx.ResponseWriter, httpError.Message, httpError.Code)
}

// setDefaultErrorHandlers sets up default error handlers
func (r *Router) setDefaultErrorHandlers() {
	// Default 404 handler
	r.notFoundHandler = func(c *Context) {
		http.Error(c.ResponseWriter, "Not Found", http.StatusNotFound)
	}

	// Default 405 handler
	r.methodNotAllowed = func(c *Context) {
		http.Error(c.ResponseWriter, "Method Not Allowed", http.StatusMethodNotAllowed)
	}

	// Default panic handler
	r.panicHandler = func(c *Context, err error) {
		fmt.Println("Panic recovered:", err)
		c.ResponseWriter.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(c.ResponseWriter, "Internal Server Error")
	}

	// Default global error handler
	r.errorHandler = func(c *Context, err error) {
		if httpError, ok := err.(*HTTPError); ok {
			http.Error(c.ResponseWriter, httpError.Message, httpError.Code)
		} else {
			fmt.Println("Error handeler Error:", err)
			http.Error(c.ResponseWriter, err.Error(), http.StatusInternalServerError)
		}
	}
}

// // Update ServeHTTP to use error handlers
// func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
// 	ctx := r.pool.Get().(*Context)
// 	ctx.Reset(w, req)
// 	defer r.pool.Put(ctx)

// 	// Panic recovery
// 	defer func() {
// 		if err := recover(); err != nil {
// 			if r.panicHandler != nil {
// 				r.panicHandler(ctx, fmt.Errorf("panic: %v\n%s", err, debug.Stack()))
// 			} else {
// 				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
// 			}
// 		}
// 	}()

// 	// Find the route
// 	node, params := r.findRoute(req.URL.Path)
// 	if node == nil {
// 		if r.notFoundHandler != nil {
// 			r.notFoundHandler(ctx)
// 		} else {
// 			http.NotFound(w, req)
// 		}
// 		return
// 	}

// 	// Set params
// 	for k, v := range params {
// 		ctx.params[k] = v
// 	}

// 	handlers, ok := node.handlers[req.Method]
// 	if !ok {
// 		if r.methodNotAllowed != nil {
// 			r.methodNotAllowed(ctx)
// 		} else {
// 			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
// 		}
// 		return
// 	}

// 	// Execute middleware chain
// 	if !r.executeMiddleware(ctx, r.middleware) {
// 		return
// 	}

// 	// Execute handler
// 	if ctx.signaltype != Abort {
// 		handlers[0](ctx)
// 	}
// }

// Error helper method for Context
func (c *Context) Error(err error) {
	if router, ok := c.store["router"].(*Router); ok {
		router.handleError(c, err)
	}
}

// HTTPError helper method for Context
func (c *Context) HTTPError(code int, message string) {
	c.Error(&HTTPError{
		Code:    code,
		Message: message,
	})
}

// func main() {
//     router := NewRouter()

//     // Custom error handlers
//     router.SetErrorHandler(func(c *Context, err error) {
//         // Global error handler
//         log.Printf("Error: %v", err)
//         if httpErr, ok := err.(*HTTPError); ok {
//             c.ResponseWriter.WriteHeader(httpErr.Code)
//             fmt.Fprintf(c.ResponseWriter, "Error: %s", httpErr.Message)
//         } else {
//             c.ResponseWriter.WriteHeader(http.StatusInternalServerError)
//             fmt.Fprintf(c.ResponseWriter, "Internal Server Error")
//         }
//     })

//     // Custom 404 handler
//     router.SetNotFoundHandler(func(c *Context) {
//         c.ResponseWriter.WriteHeader(http.StatusNotFound)
//         fmt.Fprintf(c.ResponseWriter, "Custom 404: Page not found")
//     })

//     // Custom 405 handler
//     router.SetMethodNotAllowedHandler(func(c *Context) {
//         c.ResponseWriter.WriteHeader(http.StatusMethodNotAllowed)
//         fmt.Fprintf(c.ResponseWriter, "Custom 405: Method not allowed")
//     })

//     // Custom panic handler
//     router.SetPanicHandler(func(c *Context, err error) {
//         log.Printf("Panic recovered: %v", err)
//         c.ResponseWriter.WriteHeader(http.StatusInternalServerError)
//         fmt.Fprintf(c.ResponseWriter, "Something went wrong!")
//     })

//     // Specific status code handler
//     router.OnError(http.StatusBadRequest, func(c *Context, err error) {
//         log.Printf("Bad request: %v", err)
//         c.ResponseWriter.WriteHeader(http.StatusBadRequest)
//         fmt.Fprintf(c.ResponseWriter, "Bad request: %s", err.Error())
//     })

//     // Routes that demonstrate error handling
//     router.Get("/panic", func(c *Context) {
//         panic("Something went wrong!")
//     })

//     router.Get("/error", func(c *Context) {
//         c.Error(fmt.Errorf("general error"))
//     })

//     router.Get("/bad-request", func(c *Context) {
//         c.HTTPError(http.StatusBadRequest, "Invalid parameters")
//     })

//     router.Get("/unauthorized", func(c *Context) {
//         c.HTTPError(http.StatusUnauthorized, "Please login")
//     })

//     // Middleware with error handling
//     router.Use(func(c *Context) bool {
//         auth := c.Header("Authorization")
//         if auth == "" {
//             c.HTTPError(http.StatusUnauthorized, "Authentication required")
//             return false
//         }
//         return true
//     })

//     log.Fatal(http.ListenAndServe(":8080", router))
// }

// // Custom error type
// type ValidationError struct {
// 	Field   string
// 	Message string
// }

// func (e *ValidationError) Error() string {
// 	return fmt.Sprintf("validation error: %s - %s", e.Field, e.Message)
// }

// // Validation middleware with custom error
// func validateInput(c *Context) bool {
// 	if err := validate(c); err != nil {
// 		c.Error(&HTTPError{
// 			Code:    http.StatusBadRequest,
// 			Message: "Validation failed",
// 			Err:     err,
// 		})
// 		return false
// 	}
// 	return true
// }

// Additional
// Error response formatting
type ErrorResponse struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Details interface{} `json:"details,omitempty"`
}

// JSON error handler
func JSONErrorHandler(c *Context, err error) {
	fmt.Println("JSON Error:", err)
	response := ErrorResponse{
		Code:    http.StatusInternalServerError,
		Message: "Internal Server Error",
	}

	if httpErr, ok := err.(*HTTPError); ok {
		response.Code = httpErr.Code
		response.Message = httpErr.Message
		if httpErr.Err != nil {
			response.Details = httpErr.Err.Error()
		}
	}

	c.ResponseWriter.Header().Set("Content-Type", "application/json")
	c.ResponseWriter.WriteHeader(response.Code)
	json.NewEncoder(c.ResponseWriter).Encode(response)
}

// Error handling with different formats
func (r *Router) SetErrorFormat(format string) {
	switch format {
	case "json":
		r.SetErrorHandler(JSONErrorHandler)
	case "xml":
		// Implement XML error handler
	case "html":
		// Implement HTML error handler
	}
}
