package server

import (
	"log"
	"net"

	"github.com/luyuhuang/subsocks/socks"
	"github.com/luyuhuang/subsocks/utils"
)

func (s *Server) socksHandler(conn net.Conn) {
	defer conn.Close()

	// select method
	methods, err := socks.ReadMethods(conn)
	if err != nil {
		log.Printf("Read methods failed: %s", err)
		return
	}
	method := socks.MethodNoAcceptable
	for _, m := range methods {
		if m == socks.MethodNoAuth {
			method = m
		}
	}
	if err := socks.WriteMethod(method, conn); err != nil || method == socks.MethodNoAcceptable {
		if err != nil {
			log.Printf("Write method failed: %s", err)
		} else {
			log.Printf("Methods is not acceptable")
		}
		return
	}

	// read command
	request, err := socks.ReadRequest(conn)
	if err != nil {
		log.Printf("Read command failed: %s", err)
		return
	}
	switch request.Cmd {
	case socks.CmdConnect:
		s.handleConnect(conn, request)
	case socks.CmdBind:
		s.handleBind(conn, request)
	case socks.CmdUDP:
		// unsupported, since the server based on TCP. using CmdUDPOverTCP instad.
		log.Printf("Unsupported command CmdUDP")
		if err := socks.NewReply(socks.CmdUnsupported, nil).Write(conn); err != nil {
			log.Printf("Write reply failed: %s", err)
		}
		return
	case socks.CmdUDPOverTCP:
		s.handleUDPOverTCP(conn, request)
	}
}

func (s *Server) handleConnect(conn net.Conn, req *socks.Request) {
	cc, err := net.Dial("tcp", req.Addr.String())
	if err != nil {
		log.Printf("Dial remote failed: %s", err)
		if err := socks.NewReply(socks.HostUnreachable, nil).Write(conn); err != nil {
			log.Printf("Write reply failed: %s", err)
		}
		return
	}
	defer cc.Close()

	if err := socks.NewReply(socks.Succeeded, nil).Write(conn); err != nil {
		log.Printf("Write reply failed: %s", err)
		return
	}

	if err := utils.Transport(conn, cc); err != nil {
		log.Printf("Transport failed: %s", err)
		return
	}
}

func (s *Server) handleBind(conn net.Conn, req *socks.Request) {

}

func (s *Server) handleUDPOverTCP(conn net.Conn, req *socks.Request) {

}
