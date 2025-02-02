package blueweb

import (
	"context"
	"encoding/json"

	"github.com/gorilla/websocket"
)

type wshandler struct {
	ID            string
	ex            *GoChannel
	c             *websocket.Conn
	out           *wsDataGoChannel
	isopen        bool
	clienthandler WsHandler
	server        *WsServer
}

func (wh *wshandler) Terminate() {
	wh.ex.In(struct{}{})
}

func (wh *wshandler) Dispose() {
	wh.c.Close()
	wh.ex.Close()
}

func (wh *wshandler) handle(ctx context.Context, opendata WsData, sender sender) {
	wh.isopen = true

	defer func() {
		wh.ex.Close()
		wh.isopen = false
	}()

	localsender := func(args WsData) error {
		if args != nil && args.Bool("close") {
			wh.ex.In(struct{}{})
			wh.isopen = false
		}

		sender(wh.ID, args)
		return nil
	}

	openresponse := wh.clienthandler(&WSArgs{Sender: localsender, ID: wh.ID, EventType: "ws_open", Body: opendata})

	if openresponse != nil {
		if openresponse.Bool("close") {
			return
		}

		wh.out.In(openresponse)
	}

	go func() {
		for wh.isopen {
			_, body, err := wh.c.ReadMessage()
			if err != nil || len(body) == 0 {
				wh.clienthandler(&WSArgs{Sender: localsender, Broadcase: wh.Broadcast, ID: wh.ID, EventType: "ws_error", Body: WsData{"error": err.Error()}})
				wh.ex.In(struct{}{})
				wh.isopen = false
				return
			}

			var data WsData
			err = json.Unmarshal(body, &data)
			if err != nil {
				data = WsData{"msg": string(body)}
				continue
			}

			response := wh.clienthandler(&WSArgs{
				Body:      data,
				ID:        wh.ID,
				EventType: "ws_message",
				Sender:    localsender,
			})

			if response != nil {
				if response.Bool("close") {
					wh.ex.In(struct{}{})
					wh.isopen = false
					return
				}
				wh.out.In(response)
			}
		}
	}()

out:
	for wh.isopen {
		select {
		case outgoing := <-wh.out.Out():
			err := wh.c.WriteMessage(websocket.TextMessage, []byte(outgoing.Json()))
			if err != nil {
				break out
			}
		case <-ctx.Done():
			break out
		case <-wh.ex.Out():
			break out
		}
	}

	wh.isopen = false
	wh.out.Close()
}

func (wh *wshandler) Broadcast(data WsData) {
	if wh.server == nil {
		return
	}

	wh.server.conns.broadcast(data, wh.ID)
}

func NewWsHandler(c *websocket.Conn) *wshandler {
	return &wshandler{
		ID:     ID(),
		c:      c,
		isopen: true,
		ex:     Channel(2), //  make(chan struct{}, 2),
		out:    WsDataGoChannel(10),
	}
}
