package client

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"

	"github.com/luyuhuang/subsocks/socks"
	"github.com/luyuhuang/subsocks/utils"
)

func (c *Client) wrapHTTPS(conn net.Conn) net.Conn {
	return c.wrapHTTP(tls.Client(conn, c.TLSConfig))
}

func (c *Client) wrapHTTP(conn net.Conn) net.Conn {
	return newHTTPWrapper(conn, c)
}

func isValidHTTPProxyRequest(req *http.Request) bool {
	if req.URL.Host == "" {
		return false
	}
	if req.Method != http.MethodConnect && req.URL.Scheme != "http" {
		return false
	}
	return true
}

func httpReply(statusCode int, status string) *http.Response {
	return &http.Response{
		ProtoMajor: 1,
		ProtoMinor: 1,
		StatusCode: statusCode,
		Status:     status,
	}
}

func (c *Client) httpHandler(conn net.Conn) {
	defer conn.Close()

	req, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		log.Printf("[http] read HTTP request failed: %s", err)
		return
	}
	defer req.Body.Close()

	if !isValidHTTPProxyRequest(req) {
		log.Printf("[http] invalid http proxy request: %v", req)
		httpReply(http.StatusBadRequest, "").Write(conn)
		return
	}

	host := req.URL.Hostname()
	addr := req.URL.Host
	if req.URL.Port() == "" {
		addr = net.JoinHostPort(addr, "80")
	}

	var nextHop net.Conn
	var isProxy bool
	if rule := c.Rules.getRule(host); rule == ruleProxy {
		log.Printf(`[http] dial server to connect %s for %s`, addr, conn.RemoteAddr())

		isProxy = true
		nextHop, err = c.dialServer()
		if err != nil {
			log.Printf(`[http] dial server failed: %s`, err)
			httpReply(http.StatusServiceUnavailable, "").Write(conn)
			return
		}

	} else {
		log.Printf(`[http] dial %s for %s`, addr, conn.RemoteAddr())

		nextHop, err = net.Dial("tcp", addr)
		if err != nil {
			if rule == ruleAuto {
				log.Printf(`[http] dial %s failed, dial server for %s`, addr, conn.RemoteAddr())

				isProxy = true
				nextHop, err = c.dialServer()
				if err != nil {
					log.Printf(`[http] dial server failed: %s`, err)
					httpReply(http.StatusServiceUnavailable, "").Write(conn)
					return
				}
				c.Rules.setAsProxy(host)

			} else {
				log.Printf(`[http] dial remote failed: %s`, err)
				httpReply(http.StatusServiceUnavailable, "").Write(conn)
				return
			}
		}

	}
	defer nextHop.Close()

	var dash rune
	if isProxy {
		socksAddr, _ := socks.NewAddr(addr)
		if err = socks.NewRequest(socks.CmdConnect, socksAddr).Write(nextHop); err != nil {
			log.Printf(`[http] send request failed: %s`, err)
			httpReply(http.StatusServiceUnavailable, "").Write(conn)
			return
		}
		if r, e := socks.ReadReply(nextHop); e != nil {
			log.Printf(`[http] read reply failed: %s`, err)
			httpReply(http.StatusServiceUnavailable, "").Write(conn)
			return
		} else if r.Rep != socks.Succeeded {
			log.Printf(`[http] server connect failed: %q`, r)
			httpReply(http.StatusServiceUnavailable, "").Write(conn)
			return
		}

		dash = '-'
	} else {
		dash = '='
	}

	if req.Method == http.MethodConnect {
		// the response couldn't contains 'Content-Length: 0'
		b := []byte("HTTP/1.1 200 Connection established\r\n\r\n")
		if _, err = conn.Write(b); err != nil {
			log.Printf(`[http] write reply failed: %s`, err)
			return
		}
	} else {
		req.Header.Del("Proxy-Connection")
		if err = req.Write(nextHop); err != nil {
			log.Printf(`[http] relay request failed: %s`, err)
			return
		}
	}

	log.Printf(`[http] tunnel established %s <%c> %s`, conn.RemoteAddr(), dash, addr)
	if err := utils.Transport(conn, nextHop); err != nil {
		log.Printf(`[http] transport failed: %s`, err)
	}
	log.Printf(`[http] tunnel disconnected %s >%c< %s`, conn.RemoteAddr(), dash, addr)
}

type httpWrapper struct {
	net.Conn
	client *Client
	buf    *bytes.Buffer
	ioBuf  *bufio.Reader
	auth   string
}

func newHTTPWrapper(conn net.Conn, client *Client) *httpWrapper {
	var auth string
	cfg := client.Config
	if cfg.Username != "" && cfg.Password != "" {
		s := base64.StdEncoding.EncodeToString([]byte(cfg.Username + ":" + cfg.Password))
		auth = "Basic " + s
	}
	return &httpWrapper{
		Conn:   conn,
		client: client,
		buf:    bytes.NewBuffer(make([]byte, 0, 1024)),
		ioBuf:  bufio.NewReader(conn),
		auth:   auth,
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

	if res.StatusCode != 200 {
		return 0, fmt.Errorf("Response status is not OK: %s", res.Status)
	}

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
		Header:        http.Header{},
	}
	req.Header.Add("Connection", "keep-alive")
	if h.auth != "" {
		req.Header.Add("Authorization", h.auth)
	}
	if err := req.Write(h.Conn); err != nil {
		return 0, err
	}
	return len(b), nil
}
