package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/ioutil"
	"log"
	"net"
	"time"

	"github.com/luyuhuang/subsocks/client"
	"github.com/pelletier/go-toml"
)

func launchClient(t *toml.Tree) {
	config := struct {
		Listen string `toml:"listen" default:"127.0.0.1:1080"`
		Server struct {
			Protocol string `toml:"protocol"`
			Addr     string `toml:"address"`
		} `toml:"server"`
		HTTP struct {
			Path string `toml:"path" default:"/"`
		} `toml:"http"`
		WS struct {
			Path string `toml:"path" default:"/"`
		} `toml:"ws"`
		TLS struct {
			SkipVerify bool   `toml:"skip_verify"`
			CA         string `toml:"ca"`
		} `toml:"tls"`
	}{}

	if err := t.Unmarshal(&config); err != nil {
		log.Fatalf("Parse '[client]' configuration failed: %s", err)
	}

	cli := client.NewClient(config.Listen)
	cli.Config.ServerProtocol = config.Server.Protocol
	cli.Config.ServerAddr = config.Server.Addr
	cli.Config.HTTPPath = config.HTTP.Path
	cli.Config.WSPath = config.WS.Path

	if needsTLS[config.Server.Protocol] {
		tlsConfig, err := getClientTLSConfig(config.Server.Addr, config.TLS.CA, config.TLS.SkipVerify)
		if err != nil {
			log.Fatalf("Get TLS configuration failed: %s", err)
		}
		cli.TLSConfig = tlsConfig
	}

	if err := cli.Serve(); err != nil {
		log.Fatalf("Launch client failed: %s", err)
	}
}

func getClientTLSConfig(addr, ca string, skipVerify bool) (config *tls.Config, err error) {
	rootCAs, err := loadCA(ca)
	if err != nil {
		return
	}
	serverName, _, _ := net.SplitHostPort(addr)
	if net.ParseIP(serverName) != nil { // server name is IP
		config = &tls.Config{
			InsecureSkipVerify: true,
			VerifyConnection: func(cs tls.ConnectionState) error { // verify manually
				if skipVerify {
					return nil
				}

				opts := x509.VerifyOptions{
					Roots:         rootCAs,
					CurrentTime:   time.Now(),
					Intermediates: x509.NewCertPool(),
				}

				certs := cs.PeerCertificates
				for i, cert := range certs {
					if i == 0 {
						continue
					}
					opts.Intermediates.AddCert(cert)
				}

				_, err := certs[0].Verify(opts)
				return err
			},
		}
	} else { // server name is domain
		config = &tls.Config{
			ServerName:         serverName,
			RootCAs:            rootCAs,
			InsecureSkipVerify: skipVerify,
		}
	}

	return
}

func loadCA(caFile string) (cp *x509.CertPool, err error) {
	if caFile == "" {
		return
	}
	cp = x509.NewCertPool()
	data, err := ioutil.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	if !cp.AppendCertsFromPEM(data) {
		return nil, errors.New("AppendCertsFromPEM failed")
	}
	return
}
