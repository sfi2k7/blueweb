package airouterv3

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

func v4() string {
	uuid, _ := uuid.NewRandom()
	return strings.ReplaceAll(uuid.String(), "-", "")[0:8]
}

// WebSocket types and constants
const (
	// Time allowed to write a message to the peer
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer
	pongWait = 60 * time.Second

	// Send pings to peer with this period
	pingPeriod = (pongWait * 9) / 10

	// Maximum message size allowed from peer
	maxMessageSize = 512 * 1024 // 512KB
)

// WebSocket connection upgrader
var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		// Implement your origin check logic here
		return true
	},
}

// WebSocket types
type (
	// Connection represents a WebSocket connection
	Connection struct {
		conn     *websocket.Conn
		Hub      *Hub
		Send     chan []byte
		rooms    map[string]bool
		userID   string
		metadata map[string]interface{}
		mu       sync.RWMutex
	}

	// Hub maintains the set of active connections
	Hub struct {
		// Registered connections
		connections map[*Connection]bool

		// Rooms for broadcasting
		rooms map[string]map[*Connection]bool

		// Inbound messages from the connections
		broadcast chan *Message

		// Register requests from the connections
		register chan *Connection

		// Unregister requests from connections
		unregister chan *Connection

		// Mutex for thread-safe operations
		mu sync.RWMutex
	}

	// Message represents a WebSocket message
	Message struct {
		Type   string      `json:"type"`
		Room   string      `json:"room,omitempty"`
		Data   interface{} `json:"data"`
		UserID string      `json:"userId,omitempty"`
	}
)

// NewHub creates a new Hub instance
func NewHub() *Hub {
	return &Hub{
		broadcast:   make(chan *Message),
		register:    make(chan *Connection),
		unregister:  make(chan *Connection),
		connections: make(map[*Connection]bool),
		rooms:       make(map[string]map[*Connection]bool),
	}
}

// Run starts the Hub
func (h *Hub) Run() {
	for {
		select {
		case conn := <-h.register:
			h.registerConnection(conn)
		case conn := <-h.unregister:
			h.unregisterConnection(conn)
		}
	}
}

// Connection methods
func (c *Connection) readPump() {
	defer func() {
		c.Hub.unregister <- c
		c.conn.Close()
	}()

	c.conn.SetReadLimit(maxMessageSize)
	c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				// 	c.Hub.metrics.errors.Inc()
			}
			break
		}

		var msg Message
		if err := json.Unmarshal(message, &msg); err != nil {
			continue
		}

		// Handle different message types
		switch msg.Type {
		case "join":
			c.joinRoom(msg.Room)
		case "leave":
			c.leaveRoom(msg.Room)
		case "message":
			c.Hub.broadcast <- &msg
		}
	}
}

func (c *Connection) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.Send:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)

			if err := w.Close(); err != nil {
				return
			}
		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

func (h *Hub) unregisterConnection(conn *Connection) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if _, ok := h.connections[conn]; ok {
		delete(h.connections, conn)
		close(conn.Send)
	}
}

func (h *Hub) closeAllConnections(msg *Message) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	// Closes all connections
	for conn := range h.connections {
		close(conn.Send)
		delete(h.connections, conn)
	}
}

// Add middleware support
func (conn *Connection) Use(middleware func(*Connection, []byte) bool) {
	// Implement middleware chain
}

func (ws *Connection) ManageConnection(conn *websocket.Conn) (
	reader chan []byte,
	writer chan []byte,
	closer chan struct{},
	exiter <-chan struct{}) {

	// Initialize channels
	reader = make(chan []byte)
	writer = make(chan []byte)
	closer = make(chan struct{})
	exiterChan := make(chan struct{}) // internal exiter channel
	exiter = exiterChan               // return read-only channel

	// Start goroutine to handle connection reading
	go func() {
		conn.SetReadLimit(maxMessageSize)
		conn.SetReadDeadline(time.Now().Add(pongWait))
		conn.SetPongHandler(func(string) error {
			conn.SetReadDeadline(time.Now().Add(pongWait))
			return nil
		})

		defer func() {
			if r := recover(); r != nil {
				// Handle panic and signal exit
				close(exiterChan)
			}
		}()

		for {
			select {
			case <-closer:
				return
			default:

				conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				_, messageBody, err := conn.ReadMessage()
				if err != nil {
					if !errors.Is(err, os.ErrDeadlineExceeded) {
						return
					}
					continue
				}

				select {
				case reader <- messageBody:
				case <-closer:
					return
				}
			}
		}
	}()

	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		conn.Close()
	}()

	go func() {
		for {
			select {
			case message, ok := <-writer:
				conn.SetWriteDeadline(time.Now().Add(writeWait))
				if !ok {
					conn.WriteMessage(websocket.CloseMessage, []byte{})
					return
				}

				w, err := conn.NextWriter(websocket.TextMessage)
				if err != nil {
					return
				}
				w.Write(message)

				if err := w.Close(); err != nil {
					return
				}
			case <-ticker.C:
				conn.SetWriteDeadline(time.Now().Add(writeWait))
				if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
					return
				}
			case <-closer:
				return
			}
		}
	}()

	// Start goroutine to handle cleanup
	go func() {
		defer func() {
			if r := recover(); r != nil {
				// Handle panic
				conn.Close()
			}
		}()

		// Wait for either closer or an error
		select {
		case <-closer:
			// Graceful shutdown requested
		}

		// Cleanup
		conn.Close()

		// Close all channels
		close(reader)
		close(writer)
		close(exiterChan)
	}()

	return reader, writer, closer, exiter
}

// // Integration with WebSocket connection
// func (conn *Connection) handleMessage(msg []byte) error {

// 	var message Message
// 	if err := json.Unmarshal(msg, &message); err != nil {
// 		return err
// 	}

// 	// Process message
// 	conn.Hub.broadcast <- &message
// 	return nil
// }

func (h *Hub) registerConnection(conn *Connection) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.connections[conn] = true
}

// Integrate with Router
func (r *Router) WebSocketWithManager(path string, config WebSocketConfig) {
	wsm := NewWebSocketManager(config)
	r.websockets[path] = wsm

	r.Get(path, func(c *Context) {
		wsm.HandleWebSocket(c.ResponseWriter, c.Request)
	})
}

// Router WebSocket handling
func (r *Router) WebSocket(path string, handler func(*Context, *Connection)) {
	r.Get(path, func(c *Context) {
		conn, err := upgrader.Upgrade(c.ResponseWriter, c.Request, nil)
		if err != nil {
			return
		}

		connection := &Connection{
			conn:     conn,
			Hub:      r.hub,
			Send:     make(chan []byte, 256),
			rooms:    make(map[string]bool),
			metadata: make(map[string]interface{}),
		}

		connection.Hub.register <- connection
		connection.ManageConnection(conn)

		// Allow handler to set up connection
		handler(c, connection)

		// Start the connection pumps
		go connection.writePump()
		go connection.readPump()
	})
}
