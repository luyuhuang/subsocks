package client

import (
	"log"
	"net"

	"github.com/luyuhuang/subsocks/socks"
	"github.com/luyuhuang/subsocks/utils"
)

func (c *Client) wrapSocks(conn net.Conn) (net.Conn, error) {
	return conn, nil
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
	utils.Transport(conn, ser)
}

func (c *Client) handleBind(conn net.Conn, req *socks.Request) {

}
func (c *Client) handleUDP(conn net.Conn, req *socks.Request) {

}
