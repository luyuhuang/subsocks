package client

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
)

func (c *Client) wrapHTTPS(conn net.Conn) net.Conn {
	return c.wrapHTTP(tls.Client(conn, c.TLSConfig))
}

func (c *Client) wrapHTTP(conn net.Conn) net.Conn {
	return newHTTPWrapper(conn, c)
}

type httpWrapper struct {
	net.Conn
	client *Client
	buf    *bytes.Buffer
	ioBuf  *bufio.Reader
}

func newHTTPWrapper(conn net.Conn, client *Client) *httpWrapper {
	return &httpWrapper{
		Conn:   conn,
		client: client,
		buf:    bytes.NewBuffer(make([]byte, 0, 1024)),
		ioBuf:  bufio.NewReader(conn),
	}
}

func (h *httpWrapper) Read(b []byte) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}

	if h.buf.Len() > 0 {
		return h.buf.Read(b)
	}

	res, err := http.ReadResponse(h.ioBuf, nil)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()

	if n, err = res.Body.Read(b); err != nil && err != io.EOF {
		return
	}
	if _, err = h.buf.ReadFrom(res.Body); err != nil && err != io.EOF {
		return
	}
	err = nil
	return
}

func (h *httpWrapper) Write(b []byte) (n int, err error) {
	req := http.Request{
		Method: "POST",
		Proto:  "HTTP/1.1",
		URL: &url.URL{
			Scheme: h.client.Config.ServerProtocol,
			Host:   h.client.Config.ServerAddr,
			Path:   h.client.Config.HTTPPath,
		},
		Host:          h.client.Config.ServerAddr,
		ContentLength: int64(len(b)),
		Body:          ioutil.NopCloser(bytes.NewBuffer(b)),
	}
	if err := req.Write(h.Conn); err != nil {
		return 0, err
	}
	return len(b), nil
}
