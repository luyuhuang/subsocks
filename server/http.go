package server

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"io/ioutil"
	"net"
	"net/http"
)

func (s *Server) httpsHandler(conn net.Conn) {
	s.httpHandler(tls.Server(conn, s.TLSConfig))
}

func (s *Server) httpHandler(conn net.Conn) {
	s.socksHandler(newHTTPStripper(s, conn))
}

type httpStripper struct {
	net.Conn
	server *Server
	buf    *bytes.Buffer
	ioBuf  *bufio.Reader
}

func newHTTPStripper(server *Server, conn net.Conn) *httpStripper {
	return &httpStripper{
		Conn:   conn,
		server: server,
		buf:    bytes.NewBuffer(make([]byte, 0, 1024)),
		ioBuf:  bufio.NewReader(conn),
	}
}

func (h *httpStripper) Read(b []byte) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}

	if h.buf.Len() > 0 {
		return h.buf.Read(b)
	}

	var req *http.Request
	for {
		req, err = http.ReadRequest(h.ioBuf)
		if err != nil {
			return 0, err
		}
		if req.URL.Path != h.server.Config.HTTPPath {
			req.Body.Close()
			http404Response().Write(h.Conn)
		} else {
			break
		}
	}
	defer req.Body.Close()

	if n, err = req.Body.Read(b); err != nil && err != io.EOF {
		return
	}
	if _, err = h.buf.ReadFrom(req.Body); err != nil && err != io.EOF {
		return
	}
	err = nil
	return
}

func (h *httpStripper) Write(b []byte) (n int, err error) {
	res := http.Response{
		StatusCode:    200,
		Proto:         "HTTP/1.1",
		ContentLength: int64(len(b)),
		Body:          ioutil.NopCloser(bytes.NewBuffer(b)),
	}
	if err := res.Write(h.Conn); err != nil {
		return 0, err
	}
	return len(b), nil
}

func http404Response() *http.Response {
	body := bytes.NewBufferString("<h1>404</h1><p>Not Found<p>")
	return &http.Response{
		StatusCode:    http.StatusNotFound,
		Proto:         "HTTP/1.1",
		ContentLength: int64(body.Len()),
		Body:          ioutil.NopCloser(body),
	}
}
