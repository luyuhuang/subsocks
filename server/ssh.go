package server

import (
	"errors"
	"net"

	"golang.org/x/crypto/ssh"
)

func (s *Server) SSHHandler(conn net.Conn) {
	s.socksHandler(newSSHStripper(s, conn))
}

type sshStripper struct {
	net.Conn
	server *Server

	sshChannel *ssh.Channel
}

func newSSHStripper(server *Server, conn net.Conn) *sshStripper {
	return &sshStripper{
		Conn:   conn,
		server: server,

		sshChannel: nil,
	}
}

func (s *sshStripper) Close() error {
	if s.sshChannel != nil {
		(*s.sshChannel).Close()
	}
	return s.Conn.Close()
}

func (s *sshStripper) Read(b []byte) (n int, err error) {
	if s.sshChannel == nil {
		s.sshChannel, err = s.serverInit()
		if err != nil {
			return 0, errors.New("ssh server init error")
		}
	}

	if len(b) == 0 {
		return 0, nil
	}

	n, err = (*s.sshChannel).Read(b)

	if err == nil {
		return n, err
	}
	return n, errors.New("ssh read error: " + err.Error())
}

func (s *sshStripper) Write(b []byte) (n int, err error) {
	n, err = (*s.sshChannel).Write(b)
	if err == nil {
		return n, err
	}
	return n, errors.New("ssh write error: " + err.Error())
}

func (s *sshStripper) serverInit() (*ssh.Channel, error) {
	// 监听握手
	_, chans, reqs, err := ssh.NewServerConn(s.Conn, s.server.SSHConfig)
	if err != nil {
		return nil, err
	}

	go ssh.DiscardRequests(reqs)

	// 获得channal
	for newChannel := range chans {
		// only session
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			return nil, err
		}

		// 响应shell
		go func(in <-chan *ssh.Request) {
			for req := range in {
				if req.Type == "shell" {
					req.Reply(true, []byte{})
				}
			}
		}(requests)

		return &channel, nil
	}

	return nil, errors.New("no ssh channel")
}
