package main

// Version of subsocks
const Version = "0.3.0"

var needsTLS = map[string]bool{
	"https": true,
	"wss":   true,
}
