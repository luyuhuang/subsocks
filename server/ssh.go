package server

import (
	"errors"
	"net"
	"os"

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
	// 公钥
	authorizedKeysBytes, err := os.ReadFile(s.server.SSHConfig.Cert)
	if err != nil {
		return nil, err
	}

	authorizedKeysMap := map[string]bool{}
	for len(authorizedKeysBytes) > 0 {
		pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
		if err != nil {
			return nil, err
		}

		authorizedKeysMap[string(pubKey.Marshal())] = true
		authorizedKeysBytes = rest
	}

	// 服务端配置
	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if s.server.Config.Verify(c.User(), string(pass)) {
				return nil, nil
			}
			return nil, errors.New("ssh verify error: wrong username or password")
		},
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			if authorizedKeysMap[string(pubKey.Marshal())] {
				return &ssh.Permissions{
					Extensions: map[string]string{
						"pubkey-fp": ssh.FingerprintSHA256(pubKey),
					},
				}, nil
			}
			return nil, err
		},
	}

	// 私钥
	privateBytes, err := os.ReadFile(s.server.SSHConfig.Key)
	if err != nil {
		return nil, err
	}
	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		return nil, err
	}
	config.AddHostKey(private)

	// 监听握手
	_, chans, reqs, err := ssh.NewServerConn(s.Conn, config)
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
