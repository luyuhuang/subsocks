package client

import (
	"errors"
	"io"
	"net"

	"golang.org/x/crypto/ssh"
)

func (c *Client) wrapSSH(conn net.Conn) net.Conn {
	return newSSHWrapper(conn, c)
}

type sshWrapper struct {
	net.Conn
	client    *Client
	handshark bool

	username string
	password string

	sshClient  *ssh.Client
	sshSession *ssh.Session
	sshInput   io.Writer
	sshOutput  io.Reader
}

func newSSHWrapper(conn net.Conn, client *Client) *sshWrapper {
	var wrapper = &sshWrapper{
		Conn:       conn,
		client:     client,
		handshark:  false,
		username:   client.Config.Username,
		password:   client.Config.Password,
		sshClient:  nil,
		sshSession: nil,
		sshInput:   nil,
		sshOutput:  nil,
	}
	return wrapper
}

func (s *sshWrapper) Close() error {
	if s.sshSession != nil {
		err := s.sshSession.Close()
		if err != nil {
			return err
		}
	}
	if s.sshClient != nil {
		err := s.sshClient.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *sshWrapper) Read(b []byte) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}

	n, err = s.sshOutput.Read(b)

	if err == nil {
		return n, err
	}
	return n, errors.New("ssh read error: " + err.Error())
}

func (s *sshWrapper) Write(b []byte) (n int, err error) {
	if !s.handshark {
		// dial server
		c, chans, reqs, err := ssh.NewClientConn(s.Conn, s.client.Config.Addr, s.client.SSHConfig)
		if err != nil {
			return 0, errors.New("ssh new client error")
		}
		s.sshClient = ssh.NewClient(c, chans, reqs)
		s.sshSession, err = s.sshClient.NewSession()
		if err != nil {
			return 0, errors.New("ssh new session error")
		}

		s.sshInput, err = s.sshSession.StdinPipe()
		if err != nil {
			return 0, errors.New("ssh set input error")
		}
		s.sshOutput, err = s.sshSession.StdoutPipe()
		if err != nil {
			return 0, errors.New("ssh set output error")
		}

		s.handshark = true
	}

	if len(b) == 0 {
		return 0, nil
	}
	n, err = s.sshInput.Write(b)
	if err == nil {
		return n, err
	}
	return n, errors.New("ssh write error: " + err.Error())
}
