package main

// Version of subsocks
const Version = "0.3.1"

var needsTLS = map[string]bool{
	"https": true,
	"wss":   true,
}
