package server

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"

	"github.com/luyuhuang/subsocks/utils"
)

func (s *Server) httpsHandler(conn net.Conn) {
	s.httpHandler(tls.Server(conn, s.TLSConfig))
}

func (s *Server) httpHandler(conn net.Conn) {
	s.socksHandler(newHTTPStripper(s, conn))
}

type httpStripper struct {
	net.Conn
	server     *Server
	body       io.ReadCloser
	sentHeader bool

	ioBuf *bufio.Reader
}

func newHTTPStripper(server *Server, conn net.Conn) *httpStripper {
	return &httpStripper{
		Conn:   conn,
		server: server,
		ioBuf:  bufio.NewReader(conn),
	}
}

func (h *httpStripper) Read(b []byte) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}

	for h.body == nil {
		req, err := http.ReadRequest(h.ioBuf)
		if err != nil {
			return 0, err
		}
		if h.server.Config.Verify != nil {
			if !utils.HttpBasicAuth(req.Header.Get("Authorization"), h.server.Config.Verify) {
				req.Body.Close()
				http4XXResponse(401).Write(h.Conn)
				continue
			}
		}
		if !utils.StrEQ(req.URL.Path, h.server.Config.HTTPPath) {
			req.Body.Close()
			http4XXResponse(404).Write(h.Conn)
			continue
		}
		if !utils.StrInSlice("chunked", req.TransferEncoding) {
			req.Body.Close()
			http4XXResponse(400).Write(h.Conn)
			continue
		}
		h.body = req.Body
	}

	return h.body.Read(b)
}

func (h *httpStripper) Write(b []byte) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}
	buf := bytes.NewBuffer(nil)
	if !h.sentHeader {
		buf.WriteString("HTTP/1.1 200 OK\r\n")
		buf.WriteString("Transfer-Encoding: chunked\r\n")
		buf.WriteString("\r\n")
		h.sentHeader = true
	}

	buf.WriteString(fmt.Sprintf("%X\r\n", len(b)))
	buf.Write(b)
	buf.WriteString("\r\n")
	if _, err := buf.WriteTo(h.Conn); err != nil {
		return 0, err
	}
	return len(b), nil
}

func http4XXResponse(code int) *http.Response {
	body := bytes.NewBufferString(
		fmt.Sprintf("<h1>%d</h1><p>%s<p>", code, http.StatusText(code)))
	header := make(http.Header)
	if code == 401 {
		header.Add("WWW-Authenticate", `Basic realm="auth"`)
	}
	return &http.Response{
		StatusCode:    code,
		ProtoMajor:    1,
		ProtoMinor:    1,
		ContentLength: int64(body.Len()),
		Body:          ioutil.NopCloser(body),
		Header:        header,
	}
}
