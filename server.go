package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/luyuhuang/subsocks/server"
	"github.com/luyuhuang/subsocks/utils"
	"github.com/pelletier/go-toml"
	"golang.org/x/crypto/ssh"
)

func launchServer(t *toml.Tree) {
	config := struct {
		Protocol string `toml:"protocol"`
		Addr     string `toml:"listen"`
		HTTP     struct {
			Path string `toml:"path" default:"/"`
		} `toml:"http"`
		WS struct {
			Path     string `toml:"path" default:"/"`
			Compress bool   `toml:"compress"`
		} `toml:"ws"`
		TLS struct {
			Cert string `toml:"cert"`
			Key  string `toml:"key"`
		} `toml:"tls"`
		SSH struct {
			Cert string `toml:"cert"`
			Key  string `toml:"key"`
		} `toml:"ssh"`
	}{}

	if err := t.Unmarshal(&config); err != nil {
		log.Fatalf("Parse '[server]' configuration failed: %s", err)
	}

	ser := server.NewServer(config.Protocol, config.Addr)
	ser.Config.HTTPPath = config.HTTP.Path
	ser.Config.WSPath = config.WS.Path
	ser.Config.WSCompress = config.WS.Compress

	switch users := t.Get("users").(type) {
	case string:
		ser.Config.Verify = utils.VerifyByHtpasswd(users)
	case *toml.Tree:
		m := make(map[string]string)
		if err := users.Unmarshal(&m); err != nil {
			log.Fatalf("Parse 'server.users' configuration failed: %s", err)
		}
		ser.Config.Verify = utils.VerifyByMap(m)
	}

	if needsTLS[config.Protocol] {
		tlsConfig, err := getServerTLSConfig(config.TLS.Cert, config.TLS.Key)
		if err != nil {
			log.Fatalf("Get TLS configuration failed: %s", err)
		}
		ser.TLSConfig = tlsConfig
	}

	if config.Protocol == "ssh" {
		sshConfig, err := getServerSSHConfig(config.SSH.Cert, config.SSH.Key, ser.Config)
		if err != nil {
			log.Fatalf("Get TLS configuration failed: %s", err)
		}
		ser.SSHConfig = sshConfig
	}

	if err := ser.Serve(); err != nil {
		log.Fatalf("Launch server failed: %s", err)
	}
}

func getServerTLSConfig(cert, key string) (*tls.Config, error) {
	var certificate tls.Certificate
	var err error
	if cert == "" || key == "" {
		log.Printf("Generate default TLS key pair")
		var rawCert, rawKey []byte
		rawCert, rawKey, err = genKeyPair()
		if err != nil {
			return nil, err
		}

		certificate, err = tls.X509KeyPair(rawCert, rawKey)
	} else {
		certificate, err = tls.LoadX509KeyPair(cert, key)
	}

	if err != nil {
		return nil, err
	}

	return &tls.Config{Certificates: []tls.Certificate{certificate}}, nil
}

func genKeyPair() (rawCert, rawKey []byte, err error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return
	}
	validFor := time.Hour * 24 * 365 * 10 // ten years
	notBefore := time.Now()
	notAfter := notBefore.Add(validFor)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"subsocks"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return
	}

	rawCert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	rawKey = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return
}

func getServerSSHConfig(cert string, key string, conf *server.Config) (*ssh.ServerConfig, error) {
	// 公钥
	authorizedKeysBytes, err := os.ReadFile(cert)
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
			if conf.Verify(c.User(), string(pass)) {
				return nil, nil
			}
			return nil, errors.New("ssh verify error: wrong username or password")
		},
	}

	// 私钥
	privateBytes, err := os.ReadFile(key)
	if err != nil {
		return nil, err
	}
	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		return nil, err
	}
	config.AddHostKey(private)

	return config, nil
}
