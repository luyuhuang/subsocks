package main

// Version of subsocks
const Version = "0.2.1"

var needsTLS = map[string]bool{
	"https": true,
	"wss":   true,
}
