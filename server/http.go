package server

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"strings"

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

		if h.server.Config.Verify != nil {
			if !httpBasicAuth(req.Header.Get("Authorization"), h.server.Config.Verify) {
				req.Body.Close()
				http401Response().Write(h.Conn)
				continue
			}
		}
		if !utils.StrEQ(req.URL.Path, h.server.Config.HTTPPath) {
			req.Body.Close()
			http404Response().Write(h.Conn)
			continue
		}

		break
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
	if len(b) == 0 {
		return 0, nil
	}
	res := http.Response{
		StatusCode:    200,
		ProtoMajor:    1,
		ProtoMinor:    1,
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
		ProtoMajor:    1,
		ProtoMinor:    1,
		ContentLength: int64(body.Len()),
		Body:          ioutil.NopCloser(body),
	}
}

func http401Response() *http.Response {
	body := bytes.NewBufferString("<h1>401</h1><p>Unauthorized<p>")
	header := make(http.Header)
	header.Add("WWW-Authenticate", `Basic realm="auth"`)
	return &http.Response{
		StatusCode:    http.StatusUnauthorized,
		ProtoMajor:    1,
		ProtoMinor:    1,
		ContentLength: int64(body.Len()),
		Body:          ioutil.NopCloser(body),
		Header:        header,
	}
}

func httpBasicAuth(auth string, verify func(string, string) bool) bool {
	prefix := "Basic "
	if !strings.HasPrefix(auth, prefix) {
		return false
	}
	auth = strings.Trim(auth[len(prefix):], " ")
	dc, err := base64.StdEncoding.DecodeString(auth)
	if err != nil {
		return false
	}
	groups := strings.Split(string(dc), ":")
	if len(groups) != 2 {
		return false
	}
	return verify(groups[0], groups[1])
}
