package main

import (
	"flag"
	"log"

	"github.com/luyuhuang/subsocks/client"
	"github.com/luyuhuang/subsocks/server"
	"github.com/pelletier/go-toml"
)

func main() {
	var configPath string
	flag.StringVar(&configPath, "c", "", "configuration file")
	flag.Parse()

	if configPath == "" {
		configPath = "config.toml"
		log.Printf("Using default configuration 'config.toml'")
	}

	config, err := toml.LoadFile(configPath)
	if err != nil {
		log.Fatalf("Load configuration failed: %s", err)
	}

	if c, ok := config.Get("client").(*toml.Tree); ok {
		launchClient(c)
	} else if s, ok := config.Get("server").(*toml.Tree); ok {
		launchServer(s)
	} else {
		log.Fatalf("No valid configuration '[client]' or '[server]'")
	}
}

func launchClient(t *toml.Tree) {
	config := struct {
		Listen string `toml:"listen" default:"127.0.0.1:1080"`
		Server struct {
			Protocol string `toml:"protocol"`
			Addr     string `toml:"address"`
		} `toml:"server"`
		HTTP struct {
			Path string `toml:"path"`
		} `toml:"http"`
	}{}

	if err := t.Unmarshal(&config); err != nil {
		log.Fatalf("Parse '[client]' configuration failed: %s", err)
	}

	cli := client.NewClient(config.Listen)
	cli.Config.ServerProtocol = config.Server.Protocol
	cli.Config.ServerAddr = config.Server.Addr
	cli.Config.HTTPPath = config.HTTP.Path

	if err := cli.Serve(); err != nil {
		log.Fatalf("Launch client failed: %s", err)
	}
}

func launchServer(t *toml.Tree) {
	config := struct {
		Protocol string `toml:"protocol"`
		Addr     string `toml:"listen"`
		HTTP     struct {
			Path string `toml:"path"`
		} `toml:"http"`
	}{}

	if err := t.Unmarshal(&config); err != nil {
		log.Fatalf("Parse '[server]' configuration failed: %s", err)
	}

	ser := server.NewServer(config.Protocol, config.Addr)
	ser.Config.HTTPPath = config.HTTP.Path
	if err := ser.Serve(); err != nil {
		log.Fatalf("Launch server failed: %s", err)
	}
}
