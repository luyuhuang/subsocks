package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"time"

	"github.com/luyuhuang/subsocks/server"
	"github.com/luyuhuang/subsocks/utils"
	"github.com/pelletier/go-toml"
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
		ser.SSHConfig = &server.SSHConfig{
			Cert: config.SSH.Cert,
			Key:  config.SSH.Key,
		}
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
