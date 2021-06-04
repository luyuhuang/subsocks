package client

import (
	"bufio"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"

	"github.com/luyuhuang/subsocks/socks"
)

// Client holds contexts of the client
type Client struct {
	Config    *Config
	TLSConfig *tls.Config
	Rules     *Rules
}

// NewClient creates a client
func NewClient(addr string) *Client {
	return &Client{
		Config: &Config{
			Addr: addr,
		},
	}
}

// Serve starts the server
func (c *Client) Serve() error {
	laddr, err := net.ResolveTCPAddr("tcp", c.Config.Addr)
	if err != nil {
		return err
	}
	listener, err := net.ListenTCP("tcp", laddr)
	if err != nil {
		return err
	}
	log.Printf("Client starts to listen socks5://%s", listener.Addr().String())
	log.Printf("Client starts to listen http://%s", listener.Addr().String())

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Acceptance failed: %s", err)
			continue
		}

		go func() {
			br := bufio.NewReader(conn)
			handler, err := probeProtocol(br)
			if err != nil {
				conn.Close()
				log.Printf("Probe protocol failed: %s", err)
				return
			}

			handler(c, &bufferedConn{conn, br})
		}()
	}
}

func probeProtocol(br *bufio.Reader) (func(*Client, net.Conn), error) {
	b, err := br.Peek(1)
	if err != nil {
		return nil, err
	}

	switch b[0] {
	case socks.Version:
		return (*Client).socks5Handler, nil
	default:
		return (*Client).httpHandler, nil
	}
}

type bufferedConn struct {
	net.Conn
	br *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) {
	return c.br.Read(b)
}

var protocol2wrapper = map[string]func(*Client, net.Conn) net.Conn{
	"https": (*Client).wrapHTTPS,
	"http":  (*Client).wrapHTTP,
	"socks": (*Client).wrapSocks,
	"ws":    (*Client).wrapWS,
	"wss":   (*Client).wrapWSS,
}

func (c *Client) dialServer() (net.Conn, error) {
	wrapper, ok := protocol2wrapper[c.Config.ServerProtocol]
	if !ok {
		return nil, errors.New("Unknow protocol")
	}

	conn, err := net.Dial("tcp", c.Config.ServerAddr)
	if err != nil {
		return nil, err
	}
	conn = wrapper(c, conn)

	// handshake
	if err := socks.WriteMethods([]byte{socks.MethodNoAuth}, conn); err != nil {
		conn.Close()
		return nil, err
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		conn.Close()
		return nil, err
	}
	if buf[0] != socks.Version || buf[1] != socks.MethodNoAuth {
		conn.Close()
		return nil, errors.New("Handshake failed")
	}

	return conn, nil
}

// Config is the client configuration
type Config struct {
	Addr     string
	Username string
	Password string

	Verify func(string, string) bool

	ServerProtocol string
	ServerAddr     string
	HTTPPath       string
	WSPath         string
}
