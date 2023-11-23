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

	_client  *ssh.Client
	_session *ssh.Session
	_input   io.Writer
	_output  io.Reader
}

func newSSHWrapper(conn net.Conn, client *Client) *sshWrapper {
	var wrapper = &sshWrapper{
		Conn:      conn,
		client:    client,
		handshark: false,
		username:  "subsocks",
		password:  "subsocks",
		_client:   nil,
		_session:  nil,
		_input:    nil,
		_output:   nil,
	}
	return wrapper
}

func (s *sshWrapper) Close() error {
	if s._session != nil {
		err := s._session.Close()
		if err != nil {
			return err
		}
	}
	if s._client != nil {
		err := s._client.Close()
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

	n, err = s._output.Read(b)

	if err == nil {
		return n, err
	}
	return n, errors.New("ssh read error: " + err.Error())
}

func (s *sshWrapper) Write(b []byte) (n int, err error) {
	if !s.handshark {
		sshConf := &ssh.ClientConfig{
			User: s.username,
			Auth: []ssh.AuthMethod{
				ssh.Password(s.password),
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}

		c, chans, reqs, err := ssh.NewClientConn(s.Conn, s.client.Config.Addr, sshConf)
		if err != nil {
			return 0, errors.New("ssh new client error")
		}
		s._client = ssh.NewClient(c, chans, reqs)
		s._session, err = s._client.NewSession()
		if err != nil {
			return 0, errors.New("ssh new session error")
		}

		s._input, err = s._session.StdinPipe()
		if err != nil {
			return 0, errors.New("ssh set input error")
		}
		s._output, err = s._session.StdoutPipe()
		if err != nil {
			return 0, errors.New("ssh set output error")
		}

		s.handshark = true
	}

	if len(b) == 0 {
		return 0, nil
	}
	n, err = s._input.Write(b)
	if err == nil {
		return n, err
	}
	return n, errors.New("ssh write error: " + err.Error())
}
