package client

import (
	"crypto/tls"
	"errors"
	"io"
	"net"

	"github.com/luyuhuang/subsocks/socks"
)

// Client holds contexts of the client
type Client struct {
	Config    *Config
	TLSConfig *tls.Config
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

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}

		go c.handler(conn)
	}
}

var protocol2wrapper = map[string]func(*Client, net.Conn) (net.Conn, error){
	"https": (*Client).wrapHTTPS,
	"http":  (*Client).wrapHTTP,
	"socks": (*Client).wrapSocks,
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
	newConn, err := wrapper(c, conn)
	if err != nil {
		conn.Close()
		return nil, err
	}

	// handshake
	if err := socks.WriteMethods([]byte{socks.MethodNoAuth}, newConn); err != nil {
		newConn.Close()
		return nil, err
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(newConn, buf); err != nil {
		newConn.Close()
		return nil, err
	}
	if buf[0] != socks.Version || buf[1] != socks.MethodNoAuth {
		newConn.Close()
		return nil, errors.New("Handshake failed")
	}

	return newConn, nil
}

// Config is the client configuration
type Config struct {
	Addr string

	ServerProtocol string
	ServerAddr     string
	HTTPPath       string
}
