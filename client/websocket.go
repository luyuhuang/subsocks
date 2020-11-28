package client

import (
	"bytes"
	"crypto/tls"
	"log"
	"net"
	"net/url"

	"github.com/gorilla/websocket"
)

func (c *Client) wrapWSS(conn net.Conn) net.Conn {
	return c.wrapWS(tls.Client(conn, c.TLSConfig))
}

func (c *Client) wrapWS(conn net.Conn) net.Conn {
	return newWSWrapper(conn, c)
}

type wsWrapper struct {
	net.Conn
	client *Client
	buf    *bytes.Buffer

	wsConn *websocket.Conn
}

func newWSWrapper(conn net.Conn, client *Client) *wsWrapper {
	return &wsWrapper{
		Conn:   conn,
		client: client,
		buf:    bytes.NewBuffer(make([]byte, 0, 1024)),
		wsConn: nil,
	}
}

func (w *wsWrapper) Read(b []byte) (n int, err error) {
	if w.wsConn == nil {
		w.wsConn, err = w.handshake()
		if err != nil {
			return
		}
	}

	if w.buf.Len() > 0 {
		return w.buf.Read(b)
	}

	_, p, err := w.wsConn.ReadMessage()
	if err != nil {
		return 0, err
	}
	n = copy(b, p)
	w.buf.Write(p[n:])

	return
}

func (w *wsWrapper) Write(b []byte) (n int, err error) {
	if w.wsConn == nil {
		w.wsConn, err = w.handshake()
		if err != nil {
			return
		}
	}

	err = w.wsConn.WriteMessage(websocket.BinaryMessage, b)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (w *wsWrapper) handshake() (conn *websocket.Conn, err error) {
	log.Printf("[websocket] upgrade to websocket at %s", w.client.Config.WSPath)
	u := url.URL{
		Scheme: "ws",
		Host:   w.client.Config.ServerAddr,
		Path:   w.client.Config.WSPath,
	}
	conn, res, err := websocket.NewClient(w.Conn, &u, nil, 0, 0)
	if err == nil {
		log.Printf("[websocket] connection established: %s", res.Status)
	}
	return
}
