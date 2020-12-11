package server

import (
	"crypto/tls"
	"errors"
	"log"
	"net"

	"github.com/luyuhuang/subsocks/utils"
	"github.com/tg123/go-htpasswd"
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

// SetUsersFromMap sets users from a user-password map
func (s *Server) SetUsersFromMap(users map[string]string) {
	s.Config.Verify = func(username, password string) bool {
		pw, ok := users[username]
		if !ok {
			return false
		}
		return utils.StrEQ(pw, password)
	}
}

// SetUsersFromHtpasswd sets users from a htpasswd file
func (s *Server) SetUsersFromHtpasswd(users string) {
	f, err := htpasswd.New(users, htpasswd.DefaultSystems, nil)
	if err != nil {
		log.Fatalf("Load htpasswd file failed: %s", err)
	}
	s.Config.Verify = func(username, password string) bool {
		return f.Match(username, password)
	}
}

var protocol2handler = map[string]func(*Server, net.Conn){
	"https": (*Server).httpsHandler,
	"http":  (*Server).httpHandler,
	"socks": (*Server).socksHandler,
	"ws":    (*Server).wsHandler,
	"wss":   (*Server).wssHandler,
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
	log.Printf("Server starts to listen %s://%s", s.Config.Protocol, listener.Addr().String())

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
	Protocol   string
	Addr       string
	Verify     func(string, string) bool
	HTTPPath   string
	WSPath     string
	WSCompress bool
}
