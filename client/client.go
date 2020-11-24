package client

import (
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
	log.Printf("Client starts to listen %s", listener.Addr().String())

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}

		go c.handler(conn)
	}
}

var protocol2wrapper = map[string]func(*Client, net.Conn) net.Conn{
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
	Addr string

	ServerProtocol string
	ServerAddr     string
	HTTPPath       string
}
