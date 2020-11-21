package client

import "crypto/tls"

// Client holds contexts of the client
type Client struct {
	TLSConfig *tls.Config
}

// NewClient creates a client
func NewClient() *Client {
	return &Client{}
}
