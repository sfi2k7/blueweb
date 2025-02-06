package ws

// Client-side JavaScript
const websocketClient = `
class ReloadableWebSocket {
    constructor(url, options = {}) {
        this.url = url;
        this.options = options;
        this.generation = 0;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = options.maxReconnectAttempts || 5;
        this.reconnectInterval = options.reconnectInterval || 1000;
        this.handlers = new Map();
        
        this.connect();
    }

    connect() {
        this.ws = new WebSocket(this.url);
        
        this.ws.onmessage = (event) => {
            const message = JSON.parse(event.data);
            
            // Handle reload message
            if (message.type === 'reload') {
                this.generation = message.data.generation;
                
                // Acknowledge reload
                this.send({
                    type: 'reload_ack',
                    data: { generation: this.generation }
                });
                
                // Reconnect to new server
                this.reconnect();
                return;
            }
            
            // Handle other messages
            if (this.handlers.has(message.type)) {
                this.handlers.get(message.type)(message);
            }
        };

        this.ws.onclose = () => {
            if (this.reconnectAttempts < this.maxReconnectAttempts) {
                setTimeout(() => this.reconnect(), this.reconnectInterval);
            }
        };
    }

    reconnect() {
        this.reconnectAttempts++;
        this.ws.close();
        this.connect();
    }

    send(message) {
        if (this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify(message));
        }
    }

    on(type, handler) {
        this.handlers.set(type, handler);
    }

    off(type) {
        this.handlers.delete(type);
    }
}

// Usage:
const ws = new ReloadableWebSocket('ws://localhost:8080/ws', {
    maxReconnectAttempts: 5,
    reconnectInterval: 1000
});

ws.on('message', (msg) => {
    console.log('Received:', msg);
});
`
