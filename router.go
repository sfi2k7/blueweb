package blueweb

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/julienschmidt/httprouter"
	"github.com/pkg/errors"
)

type RouterOptions struct {
	statsEndpoint string
	statstoken    string
}

type BlueWebMiddleware func(c *Context) bool
type BluewebHandler func(c *Context)

type Router struct {
	mux             *httprouter.Router
	prefix          string
	parent          *Router
	middlewares     []BlueWebMiddleware
	mustmiddlewares []BlueWebMiddleware
	port            int
	cert            string
	key             string
	so              *serveroptions
	gopt            *serveroptions
	isDev           bool
	server          *http.Server
	stopOnInt       bool
	wsserver        *WsServer
	requestCount    uint64
	rqc             *reqcount
	statstoken      string
	statsendpoint   string
	ro              *RouterOptions
}

func picohandlertohttphandler(c BluewebHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c(&Context{ResponseWriter: w, Request: r})
	})
}

// TODO Allow same options per Group
type serveroptions struct {
	skipmiddlewares bool
	skipmusts       bool
}

type Config struct {
	r *Router
}

type GroupOptions struct {
	r *Router
}

// Config gets the config for the server
func (r *Router) Config() *Config {

	if r.parent != nil {
		panic("Config can only be called on root router")
	}

	return &Config{r: r}
}

// BroadcastWs sends a message to all websockets
// data is the data to send
// exclude is a list of ids to exclude
// func (r *Router) BroadcaseWs(data WsData, exclude ...string) {
// 	r.mux.BroadcastWS(data, exclude...)
// }

// SendWs sends a message to a websocket
// id is the id of the websocket
// data is the data to send
// func (r *Router) SendWs(id string, data WsData) {
// 	r.mux.SendWS(id, data)
// }

// GroupOptions allows you to set options for a group of routes
func (r *Router) GroupOptions() *GroupOptions {
	if r.parent == nil {
		panic("Group Options can only be called on a group router")
	}

	return &GroupOptions{r: r}
}

// SkipMiddlewares skips all middlewares
// Middlewares are functions that run before the route handler
func (g *GroupOptions) SkipMiddlewares() *GroupOptions {
	g.r.gopt.skipmiddlewares = true
	return g
}

// SkipMusts skips all must middlewares
// Must middlewares are middlewares that must run after the route handler
func (g *GroupOptions) SkipMusts() *GroupOptions {
	g.r.gopt.skipmusts = true
	return g
}

// SetDev sets the server to development mode
func (c *Config) SetDev(dev bool) *Config {
	c.r.isDev = dev
	return c
}

// SetStatsToken sets the token for the stats endpoint
// token is the token to use
func (c *Config) SetStatsToken(token string) *Config {
	c.r.statstoken = token
	return c
}

// SetStatsEndpoint sets the endpoint for the stats
// endpoint is the endpoint to use
func (c *Config) SetStatsEndpoint(endpoint string) *Config {
	c.r.statsendpoint = endpoint
	return c
}

// DisableStats disables the stats endpoint
func (c *Config) DisableStats() *Config {
	c.r.statsendpoint = ""
	return c
}

// SetPort sets the port for the server
func (c *Config) SetPort(port int) *Config {
	c.r.port = port
	return c
}

// StopOnIntrupt stops the server on interrupt signal
// func (c *Config) StopOnInterrupt() *Config {
// 	c.r.mux.StopOnInt()
// 	return c
// }

// StopOnIntrupt stops the server on interrupt signal
func (c *Config) StopOnInterrupt() *Config {
	c.r.stopOnInt = true
	return c
}

// StopOnIntruptWithFunc stops the server on interrupt signal and runs a function
// fn is the function to run
// func (c *Config) StopOnInterruptWithFunc(fn func()) *Config {
// 	c.r.mux.StopOnIntWithFunc(fn)
// 	return c
// }

// SkipAllMiddlewares skips all middlewares
// Middlewares are functions that run before the route handler
func (c *Config) SkipAllMiddlewares() *Config {
	c.r.so.skipmiddlewares = true
	return c
}

// Static sets a static file server
// urlPath is the path to serve the files
// diskPath is the path to the files on disk
// func (c *Config) Static(urlPath, diskPath string) *Config {
// 	c.r.mux.Static(urlPath, diskPath)
// 	return c
// }

// UseSSL sets the server to use SSL
// cert and key are the paths to the certificate and key files
func (c *Config) UseSSL(cert, key string) *Config {
	c.r.cert = cert
	c.r.key = key
	return c
}

// SkipMusts skips all must middlewares
// Must middlewares are middlewares that must run after the route handler
func (c *Config) SkipMusts() *Config {
	c.r.so.skipmusts = true
	return c
}

// GlobalOPTIONS sets the handler for global OPTIONS requests
// This is the same as setting a route for the path with the method OPTIONS
func (c *Config) GlobalOPTIONS(fn BluewebHandler) *Config {
	c.r.mux.GlobalOPTIONS = picohandlertohttphandler(fn)
	return c
}

// HandleOPTIONS sets the server to handle OPTIONS requests
func (c *Config) HandleOPTIONS() *Config {
	c.r.mux.HandleOPTIONS = true
	return c
}

// MethodNotAllowed sets the handler for when a method is not allowed
// This is the same as setting a route for the path with the method not allowed
func (c *Config) MethodNotAllowed(fn BluewebHandler) *Config {
	c.r.mux.MethodNotAllowed = picohandlertohttphandler(fn)
	return c
}

// NotFound sets the handler for when a route is not found
// This is the same as setting a route for the path not found
func (c *Config) NotFound(fn BluewebHandler) *Config {
	c.r.mux.NotFound = picohandlertohttphandler(fn)
	return c
}

// RedirectFixedPath sets the server to redirect fixed paths
// This is the same as setting a route for the path with the fixed path
func (c *Config) RedirectFixedPath() *Config {
	c.r.mux.RedirectFixedPath = true
	return c
}

// RedirectTrailingSlash sets the server to redirect trailing slashes
// This is the same as setting a route for the path with the trailing slash
func (c *Config) RedirectTrailingSlash() *Config {
	c.r.mux.RedirectTrailingSlash = true
	return c
}

// Group sets the prefix for a group of routes
// prefix is the prefix for the group
// returns a new router
func (r *Router) Group(prefix string) *Router {
	router := &Router{so: r.so, gopt: &serveroptions{}, parent: r, mux: r.mux, prefix: path.Join(r.prefix, prefix)}
	return router
}

// Ws sets a websocket endpoint
// pattern is the path for the websocket
// fn is the handler for the websocket
// returns a broadcast function and a send function
// func (r *Router) Ws(pattern string, fn WsHandler) (broadcase func(data WsData, exclude ...string), send func(id string, data WsData)) {
// 	if r.parent != nil {
// 		panic("Websocket endpoint can only be defined at root level")
// 	}

// 	r.mux.Ws(pattern, fn)
// 	return r.mux.BroadcastWS, r.mux.SendWS
// }

// func (r *Router) WsSimple(pattern string, fn WsHandler) {
// 	if r.parent != nil {
// 		panic("Websocket endpoint can only be defined at root level")
// 	}

// 	r.mux.Ws(pattern, fn)
// }

// Ws sets a websocket endpoint
// pattern is the path for the websocket
// mh is the handler for the websocket
func (r *Router) Ws(pattern string, mh WsHandler) {
	if r.parent != nil {
		panic("Websocket endpoint can only be defined at root level")
	}

	if r.wsserver != nil {
		panic(errors.New("only one websocket server is allowed per Router"))
	}

	if mh == nil {
		panic(errors.New("websocket handler cannot be nil"))
	}

	r.wsserver = &WsServer{MessageHandler: mh, conns: &cmap{m: map[string]*wshandler{}}}
	r.mux.GET(pattern, r.middleware(r.wsserver.Handle))
}

// Get sets a GET route
// pattern is the path for the route
// fn is the handler for the route
func (r *Router) Get(pattern string, fn BluewebHandler) {
	r.mux.GET(path.Join(r.prefix, pattern), r.middleware(fn))
}

// Post sets a POST route
// pattern is the path for the route
// fn is the handler for the route
func (r *Router) Post(pattern string, fn BluewebHandler) {
	r.mux.POST(path.Join(r.prefix, pattern), r.middleware(fn))
}

// Put sets a PUT route
// pattern is the path for the route
func (r *Router) Put(pattern string, fn BluewebHandler) {
	r.mux.PUT(path.Join(r.prefix, pattern), r.middleware(fn))
}

// Delete sets a DELETE route
// pattern is the path for the route
func (r *Router) Delete(pattern string, fn BluewebHandler) {
	r.mux.DELETE(path.Join(r.prefix, pattern), r.middleware(fn))
}

// Patch sets a PATCH route
// pattern is the path for the route
func (r *Router) Patch(pattern string, fn BluewebHandler) {
	r.mux.PATCH(path.Join(r.prefix, pattern), r.middleware(fn))
}

// Options sets a OPTIONS route
// pattern is the path for the route
func (r *Router) Options(pattern string, fn BluewebHandler) {
	r.mux.OPTIONS(path.Join(r.prefix, pattern), r.middleware(fn))
}

// Must sets a must middleware that must run after the route handler
// fn is the must middleware
func (r *Router) Must(fn BlueWebMiddleware) {
	r.mustmiddlewares = append(r.mustmiddlewares, fn)
}

// Use sets a middleware
// fn is the middleware
func (r *Router) Use(fn BlueWebMiddleware) {
	r.middlewares = append(r.middlewares, fn)
}

func (r *Router) runMust(c *Context) {
	//Bottom Up - run parent MUST middlewares last
	if !r.gopt.skipmusts {
		for _, middle := range r.mustmiddlewares {
			if !middle(c) {
				break
			}
		}
	}

	if r.parent != nil {
		r.parent.runMust(c)
	}
}

func (r *Router) runMiddlewares(c *Context) bool {
	if r.so.skipmiddlewares {
		return true
	}

	if r.parent != nil {
		if !r.parent.runMiddlewares(c) {
			return false
		}
	}

	if r.gopt.skipmiddlewares {
		return true
	}

	for _, middle := range r.middlewares {
		if !middle(c) {
			return false
		}
	}

	return true
}

// middleware is a wrapper for the BlueWebHandler
// it runs the middlewares before the handler
// and the must middlewares after the handler
func (r *Router) middleware(fn BluewebHandler) httprouter.Handle {
	return func(w http.ResponseWriter, req *http.Request, p httprouter.Params) {

		//TODO: fix stats endpoint requests showing up in stats
		if len(r.statsendpoint) != 0 {
			if strings.Index(req.URL.Path, r.statsendpoint) == 0 {
				fn(&Context{ResponseWriter: w, Request: req, params: p})
				return
			}
		}

		start := time.Now()
		c := &Context{store: newStore(), ResponseWriter: w, Request: req, params: p}
		c.User = &user{}
		c.IsWebsocket = req.Header.Get("Upgrade") == "websocket"
		c.SessionId = c.UniqueId()

		r.rqc.Add(req.URL.Path)
		atomic.AddUint64(&r.requestCount, 1)

		movenext := r.runMiddlewares(c)

		if movenext {
			fn(c)
		}

		if !r.so.skipmusts {
			r.runMust(c)
		}

		c.store = nil
		c.SessionId = ""
		c.User = nil
		c.State = nil
		c.Request = nil
		c.ResponseWriter = nil

		if r.isDev {
			fmt.Printf("ts: %s, time:%s, req:%d/%d, url:%s\n", time.Now().Format(time.RFC1123), time.Since(start), r.rqc.Get(req.URL.Path), atomic.LoadUint64(&r.requestCount), req.URL)
		}
	}
}

// NewRouter creates a new router
// returns a new router
func NewRouter() *Router {
	router := &Router{
		gopt:          &serveroptions{},
		so:            &serveroptions{},
		parent:        nil,
		port:          8080,
		mux:           httprouter.New(),
		rqc:           &reqcount{r: make(map[string]uint64), s: sync.Mutex{}},
		statstoken:    "blueweb",
		statsendpoint: "/__internal__/stats/:token",
	}

	return router
}

// StartServer starts the server
// returns an error if the server fails to start
func (r *Router) StartServer() error {

	if len(r.statsendpoint) > 0 {
		r.Get(r.statsendpoint, func(c *Context) {
			token := c.params.ByName("token")
			if len(r.statstoken) > 0 && token != r.statstoken {
				c.WriteHeader(http.StatusForbidden)
				return
			}

			o := O{"Total Requests": atomic.LoadUint64(&r.requestCount),
				"RequestCountByPath": r.rqc.r,
			}

			if r.wsserver != nil {
				o["WS Connection Count"] = r.wsserver.conns.count()
			}

			c.Json(o)
		})
	}

	r.server = &http.Server{
		Addr:    ":" + strconv.Itoa(r.port),
		Handler: r.mux,
	}

	if r.stopOnInt {
		exitChan := make(chan os.Signal, 2)
		signal.Notify(exitChan, os.Interrupt, syscall.SIGTERM)

		go func() {
			<-exitChan
			fmt.Print("Shutting Down...")
			go r.wsserver.Close()
			r.StopServer()
			fmt.Println("Done!")
		}()
	}

	if r.isDev {
		fmt.Println("Listening on ", r.port)
	}

	if len(r.cert) > 0 && len(r.key) > 0 {
		return r.server.ListenAndServeTLS(r.cert, r.key)
	}

	return r.server.ListenAndServe()
}

// StopServer stops the server
// returns an error if the server fails to stop
func (r *Router) StopServer() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	err := r.server.Shutdown(ctx)
	if err == nil {
		return nil
	}

	//TODO: Add a way to force close connections (WS?)
	// r.server.RegisterOnShutdown()

	return r.server.Close()
}
