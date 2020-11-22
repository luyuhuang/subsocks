package main

import (
	"os"

	"github.com/luyuhuang/subsocks/client"
	"github.com/luyuhuang/subsocks/server"
)

func main() {
	switch os.Args[1] {
	case "server":
		server.NewServer("http", "127.0.0.1:1234").Serve()
	case "client":
		cli := client.NewClient("127.0.0.1:4321")
		cli.Config.ServerProtocol = "http"
		cli.Config.ServerAddr = "127.0.0.1:1234"
		cli.Config.HTTPPath = "/"
		cli.Serve()
	}
}
