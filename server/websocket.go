package server

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"strconv"

	"github.com/gorilla/websocket"
	"github.com/luyuhuang/subsocks/utils"
)

func (s *Server) wssHandler(conn net.Conn) {
	s.wsHandler(tls.Server(conn, s.TLSConfig))
}

func (s *Server) wsHandler(conn net.Conn) {
	s.socksHandler(newWSStripper(s, conn))
}

type wsStripper struct {
	net.Conn
	server *Server
	buf    *bytes.Buffer
	ioBuf  *bufio.Reader

	wsConn   *websocket.Conn
	upgrader *websocket.Upgrader
}

func newWSStripper(server *Server, conn net.Conn) *wsStripper {
	return &wsStripper{
		Conn:   conn,
		server: server,
		buf:    bytes.NewBuffer(make([]byte, 0, 1024)),
		ioBuf:  bufio.NewReader(conn),

		wsConn: nil,
		upgrader: &websocket.Upgrader{
			EnableCompression: server.Config.WSCompress,
		},
	}
}

func (w *wsStripper) Read(b []byte) (n int, err error) {
	if w.wsConn == nil {
		w.wsConn, err = w.handshake()
		if err != nil {
			return
		}
	}

	if len(b) == 0 {
		return 0, nil
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

func (w *wsStripper) Write(b []byte) (n int, err error) {
	if w.wsConn == nil {
		w.wsConn, err = w.handshake()
		if err != nil {
			return
		}
	}

	if len(b) == 0 {
		return 0, nil
	}

	err = w.wsConn.WriteMessage(websocket.BinaryMessage, b)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (w *wsStripper) handshake() (conn *websocket.Conn, err error) {
	var req *http.Request
	for {
		req, err = http.ReadRequest(w.ioBuf)
		if err != nil {
			return
		}

		if w.server.Config.Verify != nil {
			if !utils.HttpBasicAuth(req.Header.Get("Authorization"), w.server.Config.Verify) {
				req.Body.Close()
				http4XXResponse(401).Write(w.Conn)
				continue
			}
		}
		if !utils.StrEQ(req.URL.Path, w.server.Config.WSPath) ||
			req.Header.Get("Connection") != "Upgrade" ||
			req.Header.Get("Upgrade") != "websocket" {
			req.Body.Close()
			http4XXResponse(404).Write(w.Conn)
			continue
		}

		break
	}
	defer req.Body.Close()

	log.Printf("[websocket] upgrade request received: %s %s", req.Method, req.URL.Path)

	res := newHTTPRes4WS(w.Conn, bufio.NewReadWriter(w.ioBuf, bufio.NewWriter(w.Conn)))
	conn, err = w.upgrader.Upgrade(res, req, nil)
	if err == nil {
		log.Printf("[websocket] connection established")
	}
	return
}

type httpRes4WS struct {
	proto         string
	header        http.Header
	contentLength int64
	statusCode    int

	wroteHeader bool
	written     int64
	conn        net.Conn
	ioBuf       *bufio.ReadWriter
}

func newHTTPRes4WS(conn net.Conn, ioBuf *bufio.ReadWriter) *httpRes4WS {
	r := &httpRes4WS{
		proto:         "HTTP/1.1",
		header:        http.Header{},
		contentLength: -1,

		wroteHeader: false,
		conn:        conn,
		ioBuf:       ioBuf,
	}
	return r
}

func (r *httpRes4WS) Header() http.Header {
	return r.header
}

func (r *httpRes4WS) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}

	r.written += int64(len(b))
	if r.contentLength != -1 && r.written > r.contentLength {
		return 0, http.ErrContentLength
	}

	return r.conn.Write(b)
}

func (r *httpRes4WS) WriteHeader(statusCode int) {
	if r.wroteHeader {
		return
	}
	r.wroteHeader = true

	r.statusCode = statusCode
	if cl := r.header.Get("Content-Length"); cl != "" {
		v, err := strconv.ParseInt(cl, 10, 64)
		if err == nil && v >= 0 {
			r.contentLength = v
		} else {
			r.header.Del("Content-Length")
		}
	}

	buf := bytes.NewBuffer(make([]byte, 0, 1024))
	buf.WriteString(r.proto)
	buf.WriteString(" ")
	buf.WriteString(strconv.FormatInt(int64(r.statusCode), 10))
	buf.WriteString(" ")
	buf.WriteString(http.StatusText(r.statusCode))
	buf.WriteString("\r\n")
	r.header.Write(buf)
	buf.WriteString("\r\n")

	buf.WriteTo(r.conn)
}

func (r *httpRes4WS) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return r.conn, r.ioBuf, nil
}
