package airouterv3

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type (
	// WebSocketManager handles WebSocket connections during reload
	WebSocketManager struct {
		connections map[*websocket.Conn]*WebSocketConn
		mu          sync.RWMutex
		upgrader    websocket.Upgrader
		generation  int
		broadcast   chan *WebSocketMessage
		done        chan struct{}
		config      *WebSocketConfig
	}

	// WebSocketConn wraps a WebSocket connection with metadata
	WebSocketConn struct {
		Conn       *websocket.Conn
		ID         string
		Groups     []string
		Data       map[string]interface{}
		CreatedAt  time.Time
		Generation int
		mu         sync.RWMutex
		send       chan []byte
	}

	// WebSocketMessage represents a message for WebSocket clients
	WebSocketMessage struct {
		Type      string                 `json:"type"`
		Data      map[string]interface{} `json:"data,omitempty"`
		Group     string                 `json:"group,omitempty"`
		Recipient string                 `json:"recipient,omitempty"`
	}

	// WebSocketConfig holds WebSocket-specific configuration
	WebSocketConfig struct {
		HandshakeTimeout time.Duration
		ReadBufferSize   int
		WriteBufferSize  int
		AllowedOrigins   []string
		PingInterval     time.Duration
		PongWait         time.Duration
		WriteWait        time.Duration
		MaxMessageSize   int64
	}
)

func (wsConn *WebSocketConn) InGroup(group string) bool {
	for _, g := range wsConn.Groups {
		if g == group {
			return true
		}
	}
	return false
}

// Create new WebSocket manager
func NewWebSocketManager(config WebSocketConfig) *WebSocketManager {
	wsm := &WebSocketManager{
		connections: make(map[*websocket.Conn]*WebSocketConn),
		upgrader: websocket.Upgrader{
			HandshakeTimeout: config.HandshakeTimeout,
			ReadBufferSize:   config.ReadBufferSize,
			WriteBufferSize:  config.WriteBufferSize,
			CheckOrigin: func(r *http.Request) bool {
				origin := r.Header.Get("Origin")
				for _, allowed := range config.AllowedOrigins {
					if allowed == "*" || allowed == origin {
						return true
					}
				}
				return false
			},
		},
		broadcast: make(chan *WebSocketMessage, 1000),
		done:      make(chan struct{}),
	}

	// Start broadcast handler
	go wsm.handleBroadcasts()

	return wsm
}

// Handle WebSocket connection upgrade
func (wsm *WebSocketManager) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := wsm.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}

	wsConn := &WebSocketConn{
		Conn:       conn,
		ID:         v4(),
		Data:       make(map[string]interface{}),
		CreatedAt:  time.Now(),
		Generation: wsm.generation,
	}

	// Register connection
	wsm.mu.Lock()
	wsm.connections[conn] = wsConn
	wsm.mu.Unlock()

	// Start connection handlers
	go wsm.readPump(wsConn)
	go wsm.writePump(wsConn)
}

// Graceful reload handling for WebSocket connections
func (wsm *WebSocketManager) GracefulReload() error {
	// Increment generation
	wsm.generation++
	newGeneration := wsm.generation

	// Notify all clients of impending reload
	reloadMsg := &WebSocketMessage{
		Type: "reload",
		Data: map[string]interface{}{
			"generation": newGeneration,
			"timestamp":  time.Now(),
		},
	}

	// Broadcast reload message
	wsm.Broadcast(reloadMsg)

	// Create channel for tracking migration completion
	migrationDone := make(chan struct{})

	go func() {
		// Wait for clients to acknowledge or timeout
		timeout := time.After(30 * time.Second)
		acknowledged := make(map[*WebSocketConn]bool)

		for {
			select {
			case <-timeout:
				// Force close remaining old connections
				wsm.mu.Lock()
				for _, conn := range wsm.connections {
					if conn.Generation < newGeneration {
						conn.Conn.Close()
					}
				}
				wsm.mu.Unlock()
				close(migrationDone)
				return

			default:
				// Check if all connections are migrated
				wsm.mu.RLock()
				allMigrated := true
				for _, conn := range wsm.connections {
					if conn.Generation < newGeneration && !acknowledged[conn] {
						allMigrated = false
						break
					}
				}
				wsm.mu.RUnlock()

				if allMigrated {
					close(migrationDone)
					return
				}

				time.Sleep(100 * time.Millisecond)
			}
		}
	}()

	// Wait for migration to complete
	<-migrationDone
	return nil
}

// Implement connection reading
func (wsm *WebSocketManager) readPump(wsConn *WebSocketConn) {
	defer func() {
		wsm.removeConnection(wsConn)
		wsConn.Conn.Close()
	}()

	wsConn.Conn.SetReadLimit(wsm.config.MaxMessageSize)
	wsConn.Conn.SetReadDeadline(time.Now().Add(wsm.config.PongWait))
	wsConn.Conn.SetPongHandler(func(string) error {
		wsConn.Conn.SetReadDeadline(time.Now().Add(wsm.config.PongWait))
		return nil
	})

	for {
		_, message, err := wsConn.Conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err,
				websocket.CloseGoingAway,
				websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket read error: %v", err)
			}
			break
		}

		// Handle message
		var msg WebSocketMessage
		if err := json.Unmarshal(message, &msg); err != nil {
			continue
		}

		// Handle reload acknowledgment
		if msg.Type == "reload_ack" {
			wsConn.Generation = wsm.generation
			continue
		}

		// Process other messages...
	}
}

// Implement connection writing
func (wsm *WebSocketManager) writePump(wsConn *WebSocketConn) {
	ticker := time.NewTicker(wsm.config.PingInterval)
	defer func() {
		ticker.Stop()
		wsConn.Conn.Close()
	}()

	for {
		select {
		case message, ok := <-wsConn.send:
			wsConn.Conn.SetWriteDeadline(time.Now().Add(wsm.config.WriteWait))
			if !ok {
				wsConn.Conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := wsConn.Conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)

			// Add queued messages
			for i := 0; i < len(wsConn.send); i++ {
				w.Write([]byte{'\n'})
				w.Write(<-wsConn.send)
			}

			if err := w.Close(); err != nil {
				return
			}

		case <-ticker.C:
			wsConn.Conn.SetWriteDeadline(time.Now().Add(wsm.config.WriteWait))
			if err := wsConn.Conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// Broadcast message to all connections
func (wsm *WebSocketManager) Broadcast(msg *WebSocketMessage) {
	wsm.broadcast <- msg
}

func (wsm *WebSocketManager) removeConnection(wsConn *WebSocketConn) {
	wsm.mu.Lock()
	delete(wsm.connections, wsConn.Conn)
	wsm.mu.Unlock()
}

// Handle broadcasts
func (wsm *WebSocketManager) handleBroadcasts() {
	for {
		select {
		case msg := <-wsm.broadcast:
			wsm.mu.RLock()
			for _, conn := range wsm.connections {

				data, err := json.Marshal(msg)
				if err != nil {
					continue
				}

				select {
				case conn.send <- data:
				default:
					// Buffer full, remove slow client
					go wsm.removeConnection(conn)
				}
			}
			wsm.mu.RUnlock()

		case <-wsm.done:
			return
		}
	}
}
