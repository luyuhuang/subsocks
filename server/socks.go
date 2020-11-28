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
		log.Printf(`[socks5] read methods failed: %s`, err)
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
			log.Printf(`[socks5] write method failed: %s`, err)
		} else {
			log.Printf(`[socks5] methods is not acceptable`)
		}
		return
	}

	// read command
	request, err := socks.ReadRequest(conn)
	if err != nil {
		log.Printf(`[socks5] read command failed: %s`, err)
		return
	}
	switch request.Cmd {
	case socks.CmdConnect:
		s.handleConnect(conn, request)
	case socks.CmdBind:
		s.handleBind(conn, request)
	case socks.CmdUDP:
		// unsupported, since the server based on TCP. using CmdUDPOverTCP instad.
		log.Printf(`[socks5] unsupported command CmdUDP`)
		if err := socks.NewReply(socks.CmdUnsupported, nil).Write(conn); err != nil {
			log.Printf(`[socks5] write reply failed: %s`, err)
		}
		return
	case socks.CmdUDPOverTCP:
		s.handleUDPOverTCP(conn, request)
	}
}

func (s *Server) handleConnect(conn net.Conn, req *socks.Request) {
	log.Printf(`[socks5] "connect" connect %s for %s`, req.Addr, conn.RemoteAddr())
	newConn, err := net.Dial("tcp", req.Addr.String())
	if err != nil {
		log.Printf(`[socks5] "connect" dial remote failed: %s`, err)
		if err := socks.NewReply(socks.HostUnreachable, nil).Write(conn); err != nil {
			log.Printf(`[socks5] "connect" write reply failed: %s`, err)
		}
		return
	}
	defer newConn.Close()

	if err := socks.NewReply(socks.Succeeded, nil).Write(conn); err != nil {
		log.Printf(`[socks5] "connect" write reply failed: %s`, err)
		return
	}

	log.Printf(`[socks5] "connect" tunnel established %s <-> %s`, conn.RemoteAddr(), req.Addr)
	if err := utils.Transport(conn, newConn); err != nil {
		log.Printf(`[socks5] "connect" transport failed: %s`, err)
	}
	log.Printf(`[socks5] "connect" tunnel disconnected %s >-< %s`, conn.RemoteAddr(), req.Addr)
}

func (s *Server) handleBind(conn net.Conn, req *socks.Request) {
	log.Printf(`[socks5] "bind" bind for %s`, conn.RemoteAddr())
	listener, err := net.ListenTCP("tcp", nil)
	if err != nil {
		log.Printf(`[socks5] "bind" bind failed on listen: %s`, err)
		if err := socks.NewReply(socks.Failure, nil).Write(conn); err != nil {
			log.Printf(`[socks5] "bind" write reply failed %s`, err)
		}
		return
	}

	// first response: send listen address
	addr, _ := socks.NewAddrFromAddr(listener.Addr(), conn.LocalAddr())
	if err := socks.NewReply(socks.Succeeded, addr).Write(conn); err != nil {
		listener.Close()
		log.Printf(`[socks5] "bind" write reply failed %s`, err)
		return
	}

	newConn, err := listener.AcceptTCP()
	listener.Close()
	if err != nil {
		log.Printf(`[socks5] "bind" bind failed on accept: %s`, err)
		if err := socks.NewReply(socks.Failure, nil).Write(conn); err != nil {
			log.Printf(`[socks5] "bind" write reply failed %s`, err)
		}
		return
	}
	defer newConn.Close()

	// second response: accepted address
	raddr, _ := socks.NewAddr(newConn.RemoteAddr().String())
	if err := socks.NewReply(socks.Succeeded, raddr).Write(conn); err != nil {
		log.Printf(`[socks5] "bind" write reply failed %s`, err)
		return
	}

	log.Printf(`[socks5] "bind" tunnel established %s <-> %s`, conn.RemoteAddr(), newConn.RemoteAddr())
	if err := utils.Transport(conn, newConn); err != nil {
		log.Printf(`[socks5] "bind" transport failed: %s`, err)
	}
	log.Printf(`[socks5] "bind" tunnel disconnected %s >-< %s`, conn.RemoteAddr(), newConn.RemoteAddr())
}

func (s *Server) handleUDPOverTCP(conn net.Conn, req *socks.Request) {
	log.Printf(`[socks5] "udp-over-tcp" associate UDP for %s`, conn.RemoteAddr())
	udp, err := net.ListenUDP("udp", nil)
	if err != nil {
		log.Printf(`[socks5] "udp-over-tcp" UDP associate failed on listen: %s`, err)
		if err := socks.NewReply(socks.Failure, nil).Write(conn); err != nil {
			log.Printf(`[socks5] "udp-over-tcp" write reply failed %s`, err)
		}
		return
	}
	defer udp.Close()

	addr, _ := socks.NewAddrFromAddr(udp.LocalAddr(), conn.LocalAddr())
	if err := socks.NewReply(socks.Succeeded, addr).Write(conn); err != nil {
		log.Printf(`[socks5] "udp-over-tcp" write reply failed %s`, err)
		return
	}

	log.Printf(`[socks5] "udp-over-tcp" tunnel established %s <-> (UDP)%s`, conn.RemoteAddr(), udp.LocalAddr())
	if err := tunnelUDP(conn, udp); err != nil {
		log.Printf(`[socks5] "udp-over-tcp" tunnel UDP failed: %s`, err)
	}
	log.Printf(`[socks5] "udp-over-tcp" tunnel disconnected %s >-< (UDP)%s`, conn.RemoteAddr(), udp.LocalAddr())
}

func tunnelUDP(conn net.Conn, udp net.PacketConn) error {
	errc := make(chan error, 2)

	go func() {
		b := utils.LPool.Get().([]byte)
		defer utils.LPool.Put(b)

		for {
			n, addr, err := udp.ReadFrom(b)
			if err != nil {
				errc <- err
				return
			}

			saddr, _ := socks.NewAddr(addr.String())
			dgram := socks.NewUDPDatagram(
				socks.NewUDPHeader(uint16(n), 0, saddr), b[:n])
			if err := dgram.Write(conn); err != nil {
				errc <- err
				return
			}
		}
	}()

	go func() {
		for {
			dgram, err := socks.ReadUDPDatagram(conn)
			if err != nil {
				errc <- err
				return
			}

			addr, err := net.ResolveUDPAddr("udp", dgram.Header.Addr.String())
			if err != nil {
				continue
			}
			if _, err := udp.WriteTo(dgram.Data, addr); err != nil {
				errc <- err
				return
			}
		}
	}()

	return <-errc
}
