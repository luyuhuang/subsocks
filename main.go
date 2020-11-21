package main

import (
	"github.com/luyuhuang/subsocks/server"
)

func main() {
	ser := server.NewServer()

	// cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	// if err != nil {
	// 	fmt.Println("error", err)
	// 	return
	// }
	// ser.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}

	ser.Serve("http", "127.0.0.1:1234")
}
