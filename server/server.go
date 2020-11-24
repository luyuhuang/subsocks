package server

import (
	"crypto/tls"
	"errors"
	"log"
	"net"
)

// Server holds contexts of the server
type Server struct {
	Config    *Config
	TLSConfig *tls.Config
}

// NewServer creates a server
func NewServer(protocol, addr string) *Server {
	return &Server{
		Config: &Config{
			Protocol: protocol,
			Addr:     addr,
		},
	}
}

var protocol2handler = map[string]func(*Server, net.Conn){
	"https": (*Server).httpsHandler,
	"http":  (*Server).httpHandler,
	"socks": (*Server).socksHandler,
}

// Serve start the server
func (s *Server) Serve() error {
	handler, ok := protocol2handler[s.Config.Protocol]
	if !ok {
		return errors.New("Unknow protocol")
	}

	laddr, err := net.ResolveTCPAddr("tcp", s.Config.Addr)
	if err != nil {
		return err
	}
	listener, err := net.ListenTCP("tcp", laddr)
	if err != nil {
		return err
	}
	log.Printf("Server starts to listen %s", listener.Addr().String())

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}

		go handler(s, conn)
	}
}

// Config is the server configuration
type Config struct {
	Protocol string
	Addr     string
	HTTPPath string
}
