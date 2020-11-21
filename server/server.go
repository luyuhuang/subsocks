package server

import (
	"crypto/tls"
	"errors"
	"net"
)

// Server holds contexts of the server
type Server struct {
	TLSConfig  *tls.Config
	HTTPConfig httpConfig
}

// NewServer creates a server
func NewServer() *Server {
	return &Server{}
}

var protocol2dict = map[string]func(*Server, net.Conn){
	"https": (*Server).httpsHandler,
	"http":  (*Server).httpHandler,
	"socks": (*Server).socksHandler,
}

// Serve start the server
func (s *Server) Serve(protocol string, addr string) error {
	handler, ok := protocol2dict[protocol]
	if !ok {
		return errors.New("Unknow protocol")
	}

	laddr, err := net.ResolveTCPAddr("tcp", addr)
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

		go handler(s, conn)
	}
}
