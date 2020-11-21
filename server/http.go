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
	ioBuf  *bufio.ReadWriter
}

func newHTTPStripper(server *Server, conn net.Conn) *httpStripper {
	return &httpStripper{
		Conn:   conn,
		server: server,
		buf:    bytes.NewBuffer(make([]byte, 0, 1024)),
		ioBuf:  bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn)),
	}
}

func (h *httpStripper) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}

	p, err := h.buf.Read(b)
	if err != nil && err != io.EOF {
		return p, err
	}

	b = b[p:]
	for len(b) > 0 {
		req, err := http.ReadRequest(h.ioBuf.Reader)
		if err != nil {
			if err == io.EOF {
				h.Close()
			}
			return p, err
		}
		if req.URL.Path != h.server.HTTPConfig.path {
			continue
		}

		n, err := req.Body.Read(b)
		if err != nil {
			return p, err
		}

		b = b[n:]
		p += n

		if _, err = h.buf.ReadFrom(req.Body); err != nil && err != io.EOF {
			return p, err
		}
		req.Body.Close()
	}
	return p, nil
}

func (h *httpStripper) Write(b []byte) (n int, err error) {
	res := http.Response{
		StatusCode:    200,
		Proto:         "HTTP/1.1",
		ContentLength: int64(len(b)),
		Body:          ioutil.NopCloser(bytes.NewBuffer(b)),
	}
	res.Write(h.ioBuf)
	return 0, nil
}

type httpConfig struct {
	path string
}
