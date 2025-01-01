package blueweb

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/julienschmidt/httprouter"
	nbiowebsocket "github.com/lesismal/nbio/nbhttp/websocket"
	"github.com/pkg/errors"
)

type Context struct {
	ResponseWriter http.ResponseWriter
	Request        *http.Request
	params         httprouter.Params
	SessionId      string
	machineID      string
	IsWebsocket    bool
	AppName        string
	User           *user
	IsSecure       bool
	State          interface{}
	store          *store
}

func (c *Context) Set(k string, v interface{}) {
	c.store.Set(k, v)
}

func (c *Context) Get(k string) interface{} {
	return c.store.Get(k)
}

func (c *Context) Del(k string) {
	c.store.Del(k)
}

func (c *Context) UniqueId() string {
	return c.sessionHash()
}

func (c *Context) sessionHash() string {
	hasher := sha1.New()
	hasher.Write([]byte(c.Request.UserAgent()))
	hasher.Write([]byte(c.Request.RemoteAddr))
	hash := hasher.Sum(nil)
	return hex.EncodeToString(hash)
}

func (c *Context) Body() ([]byte, error) {
	bts, err := io.ReadAll(c.Request.Body)
	return bts, err
}

func (c *Context) ParseBody(target interface{}) error {
	bts, err := io.ReadAll(c.Request.Body)
	if err != nil {
		return err
	}

	return json.Unmarshal(bts, target)
}

func (c *Context) Query(key string) string {
	return c.Request.URL.Query().Get(key)
}

func (c *Context) QueryCaseIn(key string) string {
	for k, v := range c.Request.URL.Query() {
		if strings.EqualFold(k, key) {
			if len(v) > 0 {
				return v[0]
			}
			return ""
		}
	}
	return ""
}

func (c *Context) QueryInt(key string) (int, error) {
	v := c.Query(key)
	if len(v) == 0 {
		return 0, errors.New("key not found in path")
	}
	i, err := strconv.Atoi(v)
	if err != nil {
		return 0, errors.New("Could not parse as Int")
	}
	return i, nil
}

func (c *Context) QueryBool(key string) (bool, error) {
	v := c.Query(key)
	if len(v) == 0 {
		return false, errors.New("key not found in path")
	}

	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, errors.New("Could not parse as Bool")
	}
	return b, nil
}

func (c *Context) Form(key string) string {
	return c.Request.FormValue(key)
}

func (c *Context) Method() string {
	return c.Request.Method
}

func (c *Context) MethodLower() string {
	return strings.ToLower(c.Request.Method)
}

func (c *Context) Header(key string) string {
	return c.Request.Header.Get(key)
}

func (c *Context) RemoteIP() string {
	return c.Request.RemoteAddr
}

func (c *Context) BasicAuth() (string, string, bool) {
	return c.Request.BasicAuth()
}

func (c *Context) SetHeader(key string, value string) {
	c.ResponseWriter.Header().Set(key, value)
}

func (c *Context) File(filePath string, mimeType string) {
	c.ResponseWriter.Header().Set("content-type", mimeType)
	http.ServeFile(c.ResponseWriter, c.Request, filePath)
}

func (c *Context) FileHTML(filePath string) {
	c.ResponseWriter.Header().Set("content-type", "text/html; charset=utf-8")
	http.ServeFile(c.ResponseWriter, c.Request, filePath)
}

func (c *Context) String(str string) {
	fmt.Fprint(c, str)
}

func (c *Context) Status(statusCode int) {
	c.ResponseWriter.WriteHeader(statusCode)
}

func (c *Context) StatusWithString(statusCode int, status string) {
	c.ResponseWriter.WriteHeader(statusCode)
	c.String(status)
}

func (c *Context) Json(data interface{}) (int, error) {
	jsoned, err := json.Marshal(data)
	if err != nil {
		return 0, err
	}

	c.ResponseHeader().Add("content-type", "application/json")
	return fmt.Fprint(c, string(jsoned))
}

func (c *Context) View(filePath string, data interface{}) error {
	tmpl, err := template.ParseFiles(filePath)
	if err != nil {
		fmt.Fprint(c, err.Error())
		return err
	}

	err = tmpl.Execute(c.ResponseWriter, data)
	return err
}

func (c *Context) Params(name string) string {
	v := c.params.ByName(name)
	return v
}

func (c *Context) ResponseHeader() http.Header {
	return c.ResponseWriter.Header()
}

func (c Context) WriteHeader(n int) {
	c.ResponseWriter.WriteHeader(n)
}

func (c Context) Write(b []byte) (int, error) {
	return c.ResponseWriter.Write(b)
}

func (c *Context) SetCookie(name, value string, expireIn time.Duration) {
	cookie := &http.Cookie{
		Name:     name,
		Value:    value,
		MaxAge:   0,
		HttpOnly: true,
		Secure:   false,
		Expires:  time.Now().Add(expireIn),
		Path:     "/",
		Raw:      value,
		Unparsed: []string{value},
	}
	http.SetCookie(c.ResponseWriter, cookie)
}

func (c *Context) URL() *url.URL {
	return c.Request.URL
}

func (c *Context) HasPrefix(prefix string) bool {
	return strings.Index(c.Request.URL.Path, prefix) == 0
}

func (c *Context) IsStatic() bool {
	p := c.Request.URL.Path

	lastSlash := strings.LastIndex(p, "/")

	if lastSlash < 1 {
		return false
	}

	fielName := p[lastSlash:]
	return strings.Index(fielName, ".") > 0
}

func (c *Context) GetStaticFileExt() string {
	return path.Ext(c.Request.URL.Path)
}

func (c *Context) Host() string {
	return c.Request.Host
}

func (c *Context) Path() string {
	return c.Request.URL.Path
}

func (c *Context) W() http.ResponseWriter {
	return c.ResponseWriter
}

// func (c *Context) GetStaticDirFile() (string, string) {
// 	p := c.Request.URL.Path
// 	dir, file := filepath.Split(p)
// 	return dir, file
// }

// func (c *Context) GetStaticFile() string {
// 	_, file := c.GetStaticDirFile()
// 	return file
// }

// func (c *Context) GetStaticFilePath() string {
// 	dir, _ := c.GetStaticDirFile()
// 	return dir
// }

func (c *Context) GetCookie(name string) string {
	cookie, err := c.Request.Cookie(name)
	if err != nil {
		fmt.Println("COOKIE ERROR", err)
		return ""
	}

	val := cookie.Value
	if len(val) == 0 {
		for _, ck := range c.Request.Cookies() {
			if ck.Name == name {
				return ck.Value
			}
		}
	}
	return val
}

// func (c *Context) Mongo() (*mgo.Session, error) {
// 	if c.s != nil {
// 		return c.s, nil
// 	}

// 	s, err := getSession()
// 	c.s = s
// 	return s, err
// }

// func (c *Context) Redis() (*redis.Client, error) {
// 	if c.red != nil {
// 		return c.red, nil
// 	}

// 	c.red = redis.NewClient(&redis.Options{
// 		Addr:     redisURL,
// 		DB:       0,
// 		Network:  "tcp",
// 		Password: redisPassword,
// 	})
// 	return c.red, c.red.Ping().Err()
// }

func (c *Context) Upgrade() (*websocket.Conn, error) {
	var upgrader = websocket.Upgrader{EnableCompression: true, HandshakeTimeout: time.Second * 5, ReadBufferSize: 4096, WriteBufferSize: 4096}

	upgrader.CheckOrigin = func(r *http.Request) bool {
		return true
	}

	conn, err := upgrader.Upgrade(c.ResponseWriter, c.Request, nil)
	return conn, err
}

func (c *Context) UpgradeNBIO() (*nbiowebsocket.Conn, error) {

	u := nbiowebsocket.NewUpgrader()

	u.OnOpen(func(c *nbiowebsocket.Conn) {
		// echo
		fmt.Println("OnOpen:", c.RemoteAddr().String())
	})

	u.OnMessage(func(c *nbiowebsocket.Conn, messageType nbiowebsocket.MessageType, data []byte) {
		// echo
		fmt.Println("OnMessage:", messageType, string(data))
		c.WriteMessage(messageType, data)
	})

	u.OnClose(func(c *nbiowebsocket.Conn, err error) {
		fmt.Println("OnClose:", c.RemoteAddr().String(), err)
	})

	var upgrader = nbiowebsocket.NewUpgrader()
	//  websocket.Upgrader{EnableCompression: true, HandshakeTimeout: time.Second * 5, ReadBufferSize: 4096, WriteBufferSize: 4096}

	upgrader.CheckOrigin = func(r *http.Request) bool {
		return true
	}

	conn, err := u.Upgrade(c.ResponseWriter, c.Request, nil) // upgrader.Upgrade(c.ResponseWriter, c.Request, nil)

	return conn, err
}

func (c *Context) RemoveCookie(name string) {
	c.SetCookie(name, "", -(time.Hour * 36))
}

func (c *Context) Redirect(url string, code int) {
	http.Redirect(c.ResponseWriter, c.Request, url, code)
}

// type Socket struct {
// 	socketio.Socket
// }
