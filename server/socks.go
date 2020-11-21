package server

import (
	"io"
	"log"
	"net"

	"github.com/luyuhuang/subsocks/socks"
)

func (s *Server) socksHandler(conn net.Conn) {
	defer conn.Close()

	// select method
	methods, err := socks.ReadMethods(conn)
	if err != nil {
		log.Fatalf("Read methods failed: %s", err)
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
			log.Fatalf("Write method failed: %s", err)
		} else {
			log.Fatalf("Methods is not acceptable")
		}
		return
	}

	// read command
	request, err := socks.ReadRequest(conn)
	if err != nil {
		log.Fatalf("Read command failed: %s", err)
		return
	}
	switch request.Cmd {
	case socks.CmdConnect:
		s.handleConnect(conn, request)
	case socks.CmdBind:
		s.handleBind(conn, request)
	case socks.CmdUDP:
		// unsupported, since the server based on TCP. using CmdUDPOverTCP instad.
		log.Fatalf("Unsupported command CmdUDP")
		if err := socks.NewReply(socks.CmdUnsupported, nil).Write(conn); err != nil {
			log.Fatalf("Write reply failed: %s", err)
		}
		return
	case socks.CmdUDPOverTCP:
		s.handleUDPOverTCP(conn, request)
	}
}

func (s *Server) handleConnect(conn net.Conn, req *socks.Request) {
	cc, err := net.Dial("tcp", req.Addr.String())
	if err != nil {
		if err := socks.NewReply(socks.HostUnreachable, nil).Write(conn); err != nil {
			log.Fatalf("Write reply failed: %s", err)
		}
		return
	}
	defer cc.Close()

	if err := socks.NewReply(socks.Succeeded, nil).Write(conn); err != nil {
		log.Fatalf("Write reply failed: %s", err)
		return
	}

	if err := transport(conn, cc); err != nil {
		log.Fatalf("Transport failed: %s", err)
		return
	}
}

func (s *Server) handleBind(conn net.Conn, req *socks.Request) {

}

func (s *Server) handleUDPOverTCP(conn net.Conn, req *socks.Request) {

}

func transport(rw1, rw2 io.ReadWriter) error {
	errc := make(chan error, 1)
	go func() {
		_, err := io.Copy(rw1, rw2)
		errc <- err
	}()

	go func() {
		_, err := io.Copy(rw2, rw1)
		errc <- err
	}()

	if err := <-errc; err != nil && err == io.EOF {
		return err
	}
	return nil
}
