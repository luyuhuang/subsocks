package client

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/luyuhuang/subsocks/socks"
	"github.com/luyuhuang/subsocks/utils"
)

func (c *Client) wrapSocks(conn net.Conn) net.Conn {
	return conn
}

func (c *Client) socks5Handler(conn net.Conn) {
	defer conn.Close()

	// select method
	methods, err := socks.ReadMethods(conn)
	if err != nil {
		log.Printf(`[socks5] read methods failed: %s`, err)
		return
	}

	method := c.chooseMethod(methods)
	if err := socks.WriteMethod(method, conn); err != nil || method == socks.MethodNoAcceptable {
		if err != nil {
			log.Printf(`[socks5] write method failed: %s`, err)
		} else {
			log.Printf(`[socks5] methods is not acceptable`)
		}
		return
	}

	if err := method2Handler[method](c, conn); err != nil {
		log.Printf(`[socks5] authorization failed: %s`, err)
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
		c.handleConnect(conn, request)
	case socks.CmdBind:
		c.handleBind(conn, request)
	case socks.CmdUDP:
		c.handleUDP(conn, request)
	}
}

func (c *Client) chooseMethod(methods []uint8) uint8 {
	supportNoAuth := false
	supportUserPass := false

	for _, m := range methods {
		switch m {
		case socks.MethodNoAuth:
			supportNoAuth = c.Config.Verify == nil
		case socks.MethodUserPass:
			supportUserPass = c.Config.Verify != nil
		}
	}

	if supportUserPass {
		return socks.MethodUserPass
	} else if supportNoAuth {
		return socks.MethodNoAuth
	}
	return socks.MethodNoAcceptable
}

var method2Handler = map[uint8]func(*Client, net.Conn) error{
	socks.MethodNoAuth:   (*Client).authNoAuth,
	socks.MethodUserPass: (*Client).authUserPass,
}

func (c *Client) authNoAuth(conn net.Conn) (err error) {
	return nil
}

func (c *Client) authUserPass(conn net.Conn) (err error) {
	req, err := socks.ReadUserPassRequest(conn)
	if err != nil {
		return
	}

	if !c.Config.Verify(req.Username, req.Password) {
		if e := socks.NewUserPassResponse(socks.UserPassVer, 1).Write(conn); e != nil {
			log.Printf(`[socks5] write reply failed: %s`, e)
		}
		return fmt.Errorf(`verify user %s failed`, req.Username)
	}

	return socks.NewUserPassResponse(socks.UserPassVer, 0).Write(conn)
}

func (c *Client) handleConnect(conn net.Conn, req *socks.Request) {
	var nextHop net.Conn
	var err error
	var isProxy bool

	if rule := c.Rules.getRule(req.Addr.Host); rule == ruleProxy {
		log.Printf(`[socks5] "connect" dial server to connect %s for %s`, req.Addr, conn.RemoteAddr())

		isProxy = true
		nextHop, err = c.dialServer()
		if err != nil {
			log.Printf(`[socks5] "connect" dial server failed: %s`, err)
			if err = socks.NewReply(socks.HostUnreachable, nil).Write(conn); err != nil {
				log.Printf(`[socks5] "connect" write reply failed: %s`, err)
			}
			return
		}
		defer nextHop.Close()

	} else {
		log.Printf(`[socks5] "connect" dial %s for %s`, req.Addr, conn.RemoteAddr())

		nextHop, err = net.Dial("tcp", req.Addr.String())
		if err != nil {
			if rule == ruleAuto {
				log.Printf(`[socks5] "connect" dial %s failed, dial server for %s`, req.Addr, conn.RemoteAddr())

				isProxy = true
				nextHop, err = c.dialServer()
				if err != nil {
					log.Printf(`[socks5] "connect" dial server failed: %s`, err)
					if err = socks.NewReply(socks.HostUnreachable, nil).Write(conn); err != nil {
						log.Printf(`[socks5] "connect" write reply failed: %s`, err)
					}
					return
				}
				c.Rules.setAsProxy(req.Addr.Host)
			} else {
				log.Printf(`[socks5] "connect" dial remote failed: %s`, err)
				if err = socks.NewReply(socks.HostUnreachable, nil).Write(conn); err != nil {
					log.Printf(`[socks5] "connect" write reply failed: %s`, err)
				}
				return
			}
		}
		defer nextHop.Close()
	}

	var dash rune
	if isProxy {
		if err = req.Write(nextHop); err != nil {
			log.Printf(`[socks5] "connect" send request failed: %s`, err)
			return
		}
		dash = '-'
	} else {
		if err = socks.NewReply(socks.Succeeded, nil).Write(conn); err != nil {
			log.Printf(`[socks5] "connect" write reply failed: %s`, err)
			return
		}
		dash = '='
	}

	log.Printf(`[socks5] "connect" tunnel established %s <%c> %s`, conn.RemoteAddr(), dash, req.Addr)
	if err := utils.Transport(conn, nextHop); err != nil {
		log.Printf(`[socks5] "connect" transport failed: %s`, err)
	}
	log.Printf(`[socks5] "connect" tunnel disconnected %s >%c< %s`, conn.RemoteAddr(), dash, req.Addr)
}

func (c *Client) handleBind(conn net.Conn, req *socks.Request) {
	log.Printf(`[socks5] "bind" dial server to bind %s for %s`, req.Addr, conn.RemoteAddr())

	ser, err := c.dialServer()
	if err != nil {
		log.Printf(`[socks5] "bind" dial server failed: %s`, err)
		if err := socks.NewReply(socks.HostUnreachable, nil); err != nil {
			log.Printf(`[socks5] "bind" write reply failed: %s`, err)
		}
		return
	}
	defer ser.Close()
	if err := req.Write(ser); err != nil {
		log.Printf(`[socks5] "bind" send request failed: %s`, err)
		return
	}
	log.Printf(`[socks5] "bind" tunnel established %s <-> ?%s`, conn.RemoteAddr(), req.Addr)
	if err := utils.Transport(conn, ser); err != nil {
		log.Printf(`[socks5] Transport failed: %s`, err)
	}
	log.Printf(`[socks5] "bind" tunnel disconnected %s >-< ?%s`, conn.RemoteAddr(), req.Addr)
}

func (c *Client) handleUDP(conn net.Conn, req *socks.Request) {
	log.Printf(`[socks5] "udp" associate UDP for %s`, conn.RemoteAddr())
	udp, err := net.ListenUDP("udp", nil)
	if err != nil {
		log.Printf(`[socks5] "udp" UDP associate failed on listen: %s`, err)
		if err := socks.NewReply(socks.Failure, nil).Write(conn); err != nil {
			log.Printf(`[socks5] "udp" write reply failed %s`, err)
		}
		return
	}
	defer udp.Close()

	ser, err := c.requestServer4UDP()
	if err != nil {
		log.Printf(`[socks5] "udp" UDP associate failed on request the server: %s`, err)
		if err := socks.NewReply(socks.Failure, nil).Write(conn); err != nil {
			log.Printf(`[socks5] "udp" Write reply failed %s`, err)
		}
		return
	}
	defer ser.Close()

	addr, _ := socks.NewAddrFromAddr(udp.LocalAddr(), conn.LocalAddr())
	if err := socks.NewReply(socks.Succeeded, addr).Write(conn); err != nil {
		log.Printf(`[socks5] "udp" write reply failed %s`, err)
		return
	}

	log.Printf(`[socks5] "udp" tunnel established (UDP)%s <-> %s`, udp.LocalAddr(), c.Config.ServerAddr)
	go tunnelUDP(udp, ser)
	if err := waiting4EOF(conn); err != nil {
		log.Printf(`[socks5] "udp" waiting for EOF failed: %s`, err)
	}
	log.Printf(`[socks5] "udp" tunnel disconnected (UDP)%s >-< %s`, udp.LocalAddr(), c.Config.ServerAddr)
}

func (c *Client) requestServer4UDP() (net.Conn, error) {
	ser, err := c.dialServer()
	if err != nil {
		return nil, err
	}

	if err := socks.NewRequest(socks.CmdUDPOverTCP, nil).Write(ser); err != nil {
		ser.Close()
		return nil, err
	}
	res, err := socks.ReadReply(ser)
	if err != nil {
		ser.Close()
		return nil, err
	}
	if res.Rep != socks.Succeeded {
		ser.Close()
		return nil, fmt.Errorf("Request UDP over TCP associate failed: %q", res.Rep)
	}
	return ser, nil
}

func tunnelUDP(udp net.PacketConn, conn net.Conn) error {
	errc := make(chan error, 2)
	var clientAddr net.Addr

	go func() {
		b := utils.LPool.Get().([]byte)
		defer utils.LPool.Put(b)

		for {
			n, addr, err := udp.ReadFrom(b)
			if err != nil {
				errc <- err
				return
			}

			dgram, err := socks.ReadUDPDatagram(bytes.NewReader(b[:n]))
			if err != nil {
				errc <- err
				return
			}
			if clientAddr == nil {
				clientAddr = addr
			}
			dgram.Header.Rsv = uint16(len(dgram.Data))
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

			if clientAddr == nil {
				continue
			}
			dgram.Header.Rsv = 0
			buf := bytes.NewBuffer(nil)
			dgram.Write(buf)
			if _, err := udp.WriteTo(buf.Bytes(), clientAddr); err != nil {
				errc <- err
				return
			}
		}
	}()

	return <-errc
}

func waiting4EOF(conn net.Conn) (err error) {
	b := utils.SPool.Get().([]byte)
	defer utils.SPool.Put(b)
	for {
		_, err = conn.Read(b)
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			break
		}
	}
	return
}
