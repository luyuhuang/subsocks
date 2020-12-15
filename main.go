package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/pelletier/go-toml"
)

func main() {
	var configPath string
	var showVersion bool
	flag.StringVar(&configPath, "c", "", "configuration file, default to 'config.yml'")
	flag.BoolVar(&showVersion, "v", false, "show version information")
	flag.Parse()

	if showVersion {
		fmt.Println("Subsocks", Version)
		return
	}

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
