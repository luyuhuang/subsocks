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

func (c *Client) handler(conn net.Conn) {
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
		c.handleConnect(conn, request)
	case socks.CmdBind:
		c.handleBind(conn, request)
	case socks.CmdUDP:
		c.handleUDP(conn, request)
	}
}

func (c *Client) handleConnect(conn net.Conn, req *socks.Request) {
	ser, err := c.dialServer()
	if err != nil {
		log.Printf("Dial server failed: %s", err)
		if err := socks.NewReply(socks.HostUnreachable, nil); err != nil {
			log.Printf("Write reply failed: %s", err)
		}
		return
	}
	defer ser.Close()
	if err := req.Write(ser); err != nil {
		log.Printf("Send request failed: %s", err)
		return
	}
	if err := utils.Transport(conn, ser); err != nil {
		log.Printf("Transport failed: %s", err)
	}
}

func (c *Client) handleBind(conn net.Conn, req *socks.Request) {
	ser, err := c.dialServer()
	if err != nil {
		log.Printf("Dial server failed: %s", err)
		if err := socks.NewReply(socks.HostUnreachable, nil); err != nil {
			log.Printf("Write reply failed: %s", err)
		}
		return
	}
	defer ser.Close()
	if err := req.Write(ser); err != nil {
		log.Printf("Send request failed: %s", err)
		return
	}
	if err := utils.Transport(conn, ser); err != nil {
		log.Printf("Transport failed: %s", err)
	}
}

func (c *Client) handleUDP(conn net.Conn, req *socks.Request) {
	udp, err := net.ListenUDP("udp", nil)
	if err != nil {
		log.Printf("UDP associate failed on listen: %s", err)
		if err := socks.NewReply(socks.Failure, nil).Write(conn); err != nil {
			log.Printf("Write reply failed %s", err)
		}
		return
	}
	defer udp.Close()

	ser, err := c.requestServer4UDP()
	if err != nil {
		log.Printf("UDP associate failed on request the server: %s", err)
		if err := socks.NewReply(socks.Failure, nil).Write(conn); err != nil {
			log.Printf("Write reply failed %s", err)
		}
		return
	}
	defer ser.Close()

	addr, _ := socks.NewAddr(udp.LocalAddr().String())
	addr.Host, _, _ = net.SplitHostPort(conn.LocalAddr().String())
	if err := socks.NewReply(socks.Succeeded, addr).Write(conn); err != nil {
		log.Printf("Write reply failed %s", err)
		return
	}

	go tunnelUDP(udp, ser)
	if err := waiting4EOF(conn); err != nil {
		log.Printf("Waiting for EOF failed: %s", err)
	}
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
