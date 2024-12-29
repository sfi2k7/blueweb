package blueweb

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"
)

var WsForceClose = WsData{"close": true}

type WsServer struct {
	isclosing      bool
	MessageHandler WsHandler
	conns          *cmap
}

func (ws *WsServer) Close() {
	if ws == nil {
		return
	}

	ws.isclosing = true
	ws.conns.closeAll()
}

func (ws *WsServer) Handle(c *Context) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovering from", r)
		}
	}()

	c.IsWebsocket = true

	if ws.isclosing {
		c.WriteHeader(http.StatusInternalServerError)
		return
	}

	con, err := c.Upgrade()
	if err != nil {
		c.WriteHeader(http.StatusBadRequest)
		return
	}

	var openData = WsData{}

	for k, q := range c.URL().Query() {
		if len(q) == 0 {
			continue
		}
		openData[strings.ToLower(k)] = q[0]
	}

	for k, v := range c.r.Header {
		if len(v) == 0 {
			continue
		}

		openData[strings.ToLower(k)] = v[0]
	}

	for _, v := range c.params {
		openData[strings.ToLower(v.Key)] = v.Value
	}

	handler := NewWsHandler(con)
	handler.server = ws
	handler.clienthandler = ws.MessageHandler
	defer handler.Dispose()

	ws.conns.add(handler.ID, handler)

	openData.Set("count", ws.conns.count())

	handler.handle(context.Background(), openData)

	ws.conns.remove(handler.ID)

	ws.MessageHandler(&WSArgs{ID: handler.ID, EventType: "ws_close", Body: WsData{"count": ws.conns.count()}})

	handler.clienthandler = nil
	handler.server = nil
}

func ID() string {
	return strings.Replace(uuid.NewString(), "-", "", -1)
}
