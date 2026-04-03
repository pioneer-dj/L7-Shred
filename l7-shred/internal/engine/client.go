package engine

import (
	"github.com/l7-shred/core/internal/transport"
)

type Client struct {
	config    *transport.Config
	outbound  *transport.Outbound
	scheduler *ChaffScheduler
}

func NewClient(config *transport.Config) *Client {
	scheduler := NewChaffScheduler(config.ChaffingInterval, config.ChaffTargets)

	return &Client{
		config:    config,
		scheduler: scheduler,
	}
}

func (c *Client) Start() error {
	outbound, err := transport.NewOutbound(c.config)
	if err != nil {
		return err
	}

	c.outbound = outbound

	if err := c.outbound.Connect(); err != nil {
		return err
	}

	if c.config.ChaffingEnabled {
		c.scheduler.Start()
	}

	return nil
}

func (c *Client) Stop() error {
	if c.scheduler != nil {
		c.scheduler.Stop()
	}

	if c.outbound != nil {
		return c.outbound.Close()
	}

	return nil
}
