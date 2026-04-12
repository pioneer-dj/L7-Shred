package engine

import (
	"github.com/l7-shred/core/internal/transport"
)

type Client struct {
	config   *transport.Config
	outbound *transport.Outbound
}

func NewClient(config *transport.Config) *Client {
	return &Client{
		config: config,
	}
}

func (c *Client) Start() error {
	outbound, err := transport.NewOutbound(c.config)
	if err != nil {
		return err
	}

	c.outbound = outbound

	return c.outbound.Connect()
}

func (c *Client) Stop() error {
	if c.outbound != nil {
		return c.outbound.Close()
	}
	return nil
}
