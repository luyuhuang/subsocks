package main

// Version of subsocks
const Version = "0.1.0"

var needsTLS = map[string]bool{
	"https": true,
	"wss":   true,
}
